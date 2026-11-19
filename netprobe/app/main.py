"""netprobe: VLAN (VXLAN の net<VLAN>) の側から診断のパケットを出す。

AI チャット (aichat) から HTTP で呼ばれる。コマンドは固定の引数で実行し、シェルは使わない。
安全のため、次を守る:
- 送り先は IP に直してから検査する (ループバック、リンクローカル、マルチキャスト、未指定は不可)。
- TCP と HTTP は決まったポートだけ。HTTP は本文を読まない。
- 全体で 1 分に 30 回まで。
- 経路は VLAN ごとの表 (ip rule + ip route) で、その VLAN の IP から出たものを、その VLAN の
  ゲートウェイ (FortiGate の software switch) に向ける。他の経路は変えない。
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from contextlib import asynccontextmanager

import dns.exception
import dns.resolver
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

log = logging.getLogger("netprobe")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# VLAN -> そのゲートウェイ (software switch の IP)。DHCP が返す経路は CNI が捨てるので、ここで与える
GATEWAYS: dict[int, str] = {int(k): v for k, v in (
    p.split("=") for p in os.environ.get("VLAN_GATEWAYS", "10=10.10.0.1,20=10.10.16.1").split(","))}
ALLOWED_PORTS = {22, 25, 53, 80, 123, 443, 445, 2049, 3000, 5000, 8000, 8080, 8443, 9000, 9090}
RATE = (30, 60)
CHECKS = {"ping", "arping", "traceroute", "dns", "tcp", "http"}

_state: dict[int, dict] = {}   # vlan -> {"iface", "ip", "gateway", "ok", "error"}
_calls: list[float] = []
_lock = threading.Lock()


def _run(cmd: list[str], timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _setup_vlan(vlan: int, gw: str) -> dict:
    """net<VLAN> の IP を読み、その IP から出るパケットをゲートウェイに向ける。"""
    iface = f"net{vlan}"
    r = _run(["ip", "-j", "-4", "addr", "show", "dev", iface])
    addrs = json.loads(r.stdout or "[]") if r.returncode == 0 else []
    ips = [a["local"] for i in addrs for a in i.get("addr_info", [])]
    if not ips:
        return {"iface": iface, "ok": False, "error": f"{iface} に IPv4 アドレスがありません (DHCP の取得待ちか失敗)"}
    ip, table = ips[0], str(100 + vlan)
    for cmd in (["ip", "route", "replace", "default", "via", gw, "dev", iface, "table", table],
                ["ip", "rule", "del", "from", ip, "lookup", table],   # 重複を避ける (なければ失敗してよい)
                ["ip", "rule", "add", "from", ip, "lookup", table]):
        out = _run(cmd)
        if out.returncode != 0 and cmd[2] != "del":
            return {"iface": iface, "ip": ip, "ok": False, "error": out.stderr.strip()}
    return {"iface": iface, "ip": ip, "gateway": gw, "ok": True}


def _refresh() -> None:
    """起動時と、必要なときに経路を整える。DHCP のリースが更新されて IP が変わったときにも対応する。"""
    for vlan, gw in GATEWAYS.items():
        _state[vlan] = _setup_vlan(vlan, gw)


@asynccontextmanager
async def lifespan(_: FastAPI):
    def wait_and_setup() -> None:
        for _ in range(30):  # Pod の起動直後は DHCP の取得が終わっていないことがある
            _refresh()
            if all(s.get("ok") for s in _state.values()):
                break
            time.sleep(2)
        log.info("vlans: %s", _state)
    threading.Thread(target=wait_and_setup, daemon=True).start()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)


class Probe(BaseModel):
    vlan: int
    check: str
    target: str = Field(min_length=1, max_length=253)
    port: int = 0
    count: int = 4
    record_type: str = "A"
    server: str = ""


def _rate_limit() -> None:
    now = time.time()
    with _lock:
        _calls[:] = [t for t in _calls if now - t < RATE[1]]
        if len(_calls) >= RATE[0]:
            raise HTTPException(429, "診断が多いので少し待ってください (1 分に 30 回まで)。")
        _calls.append(now)


def _ok_ip(ip: str) -> str:
    """IP として正しく、送ってよいものを返す。IP でなければ ValueError、禁止なら HTTPException。"""
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved:
        raise HTTPException(400, f"{ip} には送れません (ループバック、リンクローカル、マルチキャストなど)。")
    return str(a)


def _vlan(vlan: int) -> dict:
    s = _state.get(vlan)
    if s is None:
        raise HTTPException(400, f"VLAN {vlan} は使えません。使えるもの: {sorted(GATEWAYS)}")
    if not s.get("ok"):
        _refresh()
        s = _state[vlan]
    if not s.get("ok"):
        raise HTTPException(503, f"VLAN {vlan} の準備ができていません: {s.get('error')}")
    return s


def _dns(name: str, rt: str, server: str, src: str, timeout: float = 4) -> list[str]:
    res = dns.resolver.Resolver(configure=False)
    res.nameservers, res.lifetime, res.timeout = [server], timeout, timeout
    res.source = src
    return [r.to_text() for r in res.resolve(name, rt, raise_on_no_answer=True)]


def _target_ip(host: str, s: dict) -> str:
    """IP ならそのまま、名前なら VLAN のゲートウェイの DNS (software switch) で引く。"""
    host = host.strip().rstrip(".")
    try:
        return _ok_ip(host)
    except ValueError:
        pass
    if any(c in host for c in " /\\@?#"):
        raise HTTPException(400, f"宛先が正しくありません: {host!r}")
    try:
        return _ok_ip(_dns(host, "A", s["gateway"], s["ip"])[0])
    except (dns.exception.DNSException, IndexError) as e:
        raise HTTPException(400, f"{host} の名前を VLAN の DNS ({s['gateway']}) で引けませんでした "
                                 f"({type(e).__name__})。") from e


def _cmd_out(r: subprocess.CompletedProcess) -> str:
    return ((r.stdout or "") + (r.stderr or "")).strip()[-3000:]


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/readyz")
def readyz() -> dict:
    """全 VLAN の IP と経路の準備ができたときだけ Ready にする (起動した側が待てるように)。"""
    if not _state or not all(s.get("ok") for s in _state.values()):
        raise HTTPException(503, "VLAN の準備中です")
    return {"ok": True}


@app.get("/v1/interfaces")
def interfaces() -> dict:
    return {"vlans": {str(k): v for k, v in _state.items()}}


@app.post("/v1/probe")
def probe(p: Probe) -> dict:
    if p.check not in CHECKS:
        raise HTTPException(400, f"check は {sorted(CHECKS)} のどれかです。")
    s = _vlan(p.vlan)
    _rate_limit()
    log.info("probe vlan=%s %s %s port=%s", p.vlan, p.check, p.target, p.port)
    src, iface = s["ip"], s["iface"]
    head = f"[VLAN {p.vlan} {iface} {src} から]"

    if p.check == "dns":
        try:
            server = _ok_ip(p.server.strip()) if p.server.strip() else s["gateway"]
        except ValueError as e:
            raise HTTPException(400, "server は IP アドレスで指定してください。") from e
        rt = p.record_type.strip().upper()
        if rt not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SRV"}:
            raise HTTPException(400, f"対応していない種類です: {p.record_type}")
        t0 = time.monotonic()
        try:
            ans = _dns(p.target.strip(), rt, server, src, 5)
        except dns.resolver.NXDOMAIN:
            return {"result": f"{head} {p.target} {rt} @{server}: NXDOMAIN (その名前は存在しません)"}
        except dns.resolver.NoAnswer:
            return {"result": f"{head} {p.target} {rt} @{server}: 名前はあるが {rt} のレコードがありません"}
        except dns.exception.Timeout:
            return {"result": f"{head} {p.target} {rt} @{server}: タイムアウト (サーバーに届かない)"}
        except dns.exception.DNSException as e:
            return {"result": f"{head} {p.target} {rt} @{server}: エラー {type(e).__name__}"}
        ms = (time.monotonic() - t0) * 1000
        return {"result": f"{head} {p.target} {rt} @{server}: {ms:.0f} ms\n" + "\n".join(f"  {a}" for a in ans)}

    ip = _target_ip(p.target, s)
    if p.check == "ping":
        r = _run(["ping", "-n", "-c", str(max(1, min(p.count, 10))), "-W", "2", "-I", src, ip], 30)
        return {"result": f"{head} ping {p.target} ({ip})\n{_cmd_out(r)}"}
    if p.check == "arping":
        # ARP で同じ L2 にいる相手の MAC を調べる。ゲートウェイや同じ VLAN の機器向け
        r = _run(["arping", "-c", str(max(1, min(p.count, 10))), "-w", "5", "-I", iface, "-s", src, ip], 30)
        return {"result": f"{head} arping {ip}\n{_cmd_out(r)}"}
    if p.check == "traceroute":
        r = _run(["traceroute", "-n", "-I", "-s", src, "-m", "15", "-w", "1", "-q", "1", ip], 40)
        return {"result": f"{head} traceroute {ip}\n{_cmd_out(r)}"}

    # tcp / http
    port = p.port
    path, host_hdr, scheme = "/", p.target, "http"
    if p.check == "http":
        u = urllib.parse.urlsplit(p.target if "://" in p.target else f"http://{p.target}")
        if u.scheme not in ("http", "https"):
            raise HTTPException(400, "http:// か https:// の URL を指定してください。")
        scheme, host_hdr = u.scheme, u.netloc
        port = u.port or (443 if scheme == "https" else 80)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        ip = _target_ip(u.hostname or "", s)
    if port not in ALLOWED_PORTS:
        raise HTTPException(400, f"このポートは調べられません。使えるもの: {sorted(ALLOWED_PORTS)}")
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((ip, port), timeout=4, source_address=(src, 0))
        ms = (time.monotonic() - t0) * 1000
        if p.check == "tcp":
            sock.close()
            return {"result": f"{head} {ip}:{port}: 接続できました ({ms:.0f} ms)"}
        if scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=u.hostname)
        sock.settimeout(8)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nUser-Agent: netprobe\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        sock.close()
    except ConnectionRefusedError:
        return {"result": f"{head} {ip}:{port}: 接続を拒否されました (届いているがポートが閉じている)"}
    except (TimeoutError, socket.timeout):
        return {"result": f"{head} {ip}:{port}: タイムアウト (途中の FortiGate のポリシーで捨てられている疑い)"}
    except ssl.SSLError as e:
        return {"result": f"{head} {ip}:{port}: TLS エラー ({getattr(e, 'reason', None) or type(e).__name__})"}
    except OSError as e:
        return {"result": f"{head} {ip}:{port}: 失敗 ({e.strerror or type(e).__name__})"}
    lines = buf.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    keep = ("server", "location", "content-type", "content-length")
    hdrs = [h[:200] for h in lines[1:] if h.split(":", 1)[0].lower() in keep]
    total = (time.monotonic() - t0) * 1000
    return {"result": f"{head} {p.target} ({ip}:{port}) 接続 {ms:.0f} ms、応答まで {total:.0f} ms\n  "
                      + "\n  ".join([lines[0] or "(応答なし)"] + hdrs)}
