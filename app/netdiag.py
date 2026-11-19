"""ネットワーク診断のツール (ping、DNS、TCP、HTTP)。Pod の中から実行するので、Pod から見た到達性がわかる。

画面にログインがなく誰でも質問できるので、宛先と回数を絞る:
- ループバック、リンクローカル (クラウドのメタデータなど)、マルチキャスト、未指定アドレスには送らない。
- TCP と HTTP は、よく使うポートだけ。HTTP は本文を読まず、状態コードと一部のヘッダーだけ返す。
- 全体で 1 分に 30 回まで。
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
import socket
import ssl
import threading
import time
import urllib.parse

import dns.exception
import dns.resolver
from icmplib import ICMPLibError, ping as _icmp_ping

ALLOWED_PORTS = {22, 25, 53, 80, 123, 443, 445, 2049, 3000, 5000, 8000, 8080, 8443, 9000, 9090}
RATE = (30, 60)  # 60 秒に 30 回まで
_calls: list[float] = []
_lock = threading.Lock()


def _rate_limit() -> None:
    now = time.time()
    with _lock:
        _calls[:] = [t for t in _calls if now - t < RATE[1]]
        if len(_calls) >= RATE[0]:
            raise ValueError("診断が多いので少し待ってください (1 分に 30 回まで)。")
        _calls.append(now)


def _check_ip(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved:
        raise ValueError(f"{ip} には送れません (ループバック、リンクローカル、マルチキャストなど)。")
    return str(a)


def _resolve(host: str) -> list[str]:
    """宛先を IP に直し、送ってよいものだけ返す。"""
    host = host.strip().rstrip(".")
    if not host or len(host) > 253 or any(c in host for c in " /\\@?#"):
        raise ValueError(f"宛先が正しくありません: {host!r}")
    try:
        return [_check_ip(host)]
    except ValueError as e:
        if "には送れません" in str(e):
            raise
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"{host} の名前を引けませんでした ({e.strerror})。") from e
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    return [_check_ip(ip) for ip in ips]


def ping(host: str, count: int = 4) -> str:
    """ICMP の ping を打つ (Pod から宛先へ)。到達性、遅延、パケットロスがわかる。

    Args:
        host: ホスト名か IP アドレス。例: 192.168.99.1, ai.svc.technotut.net, 1.1.1.1
        count: 回数 (1〜10)。
    """
    _rate_limit()
    ip = _resolve(host)[0]
    try:
        r = _icmp_ping(ip, count=max(1, min(int(count), 10)), interval=0.3, timeout=2, privileged=False)
    except ICMPLibError as e:
        return f"ping を実行できませんでした: {e}"
    state = "到達できました" if r.is_alive else "応答がありません"
    out = [f"{host} ({ip}): {state}", f"送信 {r.packets_sent}、受信 {r.packets_received}、ロス {r.packet_loss:.0%}"]
    if r.packets_received:
        out.append(f"RTT 最小/平均/最大 = {r.min_rtt:.1f}/{r.avg_rtt:.1f}/{r.max_rtt:.1f} ms")
    if not r.is_alive:
        out.append("(ICMP を落とす機器もあるので、応答がなくても通信できないとは限りません。tcp_check も試す)")
    return "\n".join(out)


def dns_lookup(name: str, record_type: str = "A", server: str = "") -> str:
    """DNS を引く (nslookup / dig 相当)。応答、遅延、エラーの種類 (NXDOMAIN、タイムアウトなど) がわかる。

    Args:
        name: 引く名前。例: github.com, ai.svc.technotut.net
        record_type: A, AAAA, CNAME, MX, NS, TXT, PTR, SRV のどれか。
        server: 問い合わせる DNS サーバーの IP。空なら Pod が使う DNS (クラスタの CoreDNS)。
    """
    _rate_limit()
    rt = record_type.strip().upper()
    if rt not in {"A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SRV"}:
        raise ValueError(f"対応していない種類です: {record_type}")
    res = dns.resolver.Resolver()  # /etc/resolv.conf を使う
    res.lifetime = 5
    if server.strip():
        res.nameservers = [_check_ip(server.strip())]
    used = ", ".join(res.nameservers)
    t0 = time.monotonic()
    try:
        ans = res.resolve(name.strip(), rt, raise_on_no_answer=True)
    except dns.resolver.NXDOMAIN:
        return f"{name} {rt} @{used}: NXDOMAIN (その名前は存在しません)"
    except dns.resolver.NoAnswer:
        return f"{name} {rt} @{used}: 名前はあるが {rt} のレコードがありません"
    except dns.exception.Timeout:
        return f"{name} {rt} @{used}: タイムアウト (DNS サーバーに届かないか、応答がありません)"
    except dns.exception.DNSException as e:
        return f"{name} {rt} @{used}: エラー {type(e).__name__}"
    ms = (time.monotonic() - t0) * 1000
    lines = [f"{name} {rt} @{used}: {ms:.0f} ms, TTL {ans.rrset.ttl}"]
    lines += [f"  {r.to_text()}" for r in ans]
    return "\n".join(lines)


def tcp_check(host: str, port: int) -> str:
    """TCP で接続できるか調べる (nc -z 相当)。ポートが開いているか、ファイアウォールに止められているかを切り分ける。

    Args:
        host: ホスト名か IP アドレス。
        port: ポート番号。使えるのは 22, 25, 53, 80, 123, 443, 445, 2049, 3000, 5000, 8000, 8080, 8443, 9000, 9090。
    """
    _rate_limit()
    port = int(port)
    if port not in ALLOWED_PORTS:
        raise ValueError(f"このポートは調べられません。使えるもの: {sorted(ALLOWED_PORTS)}")
    ip = _resolve(host)[0]
    t0 = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=4):
            ms = (time.monotonic() - t0) * 1000
            return f"{host}:{port} ({ip}): 接続できました ({ms:.0f} ms)"
    except ConnectionRefusedError:
        return f"{host}:{port} ({ip}): 接続を拒否されました (宛先には届いているが、そのポートで待ち受けていません)"
    except (TimeoutError, socket.timeout):
        return f"{host}:{port} ({ip}): タイムアウト (途中のファイアウォールで捨てられているか、宛先が応答しません)"
    except OSError as e:
        return f"{host}:{port} ({ip}): 失敗 ({e.strerror or type(e).__name__})"


def http_check(url: str) -> str:
    """HTTP(S) で GET して、状態コード、遅延、リダイレクト先、TLS の問題を返す (curl -I 相当)。本文は返さない。

    Args:
        url: http:// か https:// で始まる URL。例: https://github.com, http://ai.svc.technotut.net/healthz
    """
    _rate_limit()
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("http:// か https:// で始まる URL を指定してください。")
    port = u.port or (443 if u.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise ValueError(f"このポートは調べられません。使えるもの: {sorted(ALLOWED_PORTS)}")
    ip = _resolve(u.hostname)[0]
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((ip, port), timeout=5)
        t_conn = (time.monotonic() - t0) * 1000
        sock = raw
        if u.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname)
        t_tls = (time.monotonic() - t0) * 1000
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        sock.settimeout(8)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {u.netloc}\r\nUser-Agent: infra-assistant\r\n"
                     "Accept: */*\r\nConnection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 16384:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
        sock.close()
    except ssl.SSLCertVerificationError as e:
        return f"{url}: TLS 証明書の検証に失敗しました ({e.verify_message})"
    except ssl.SSLError as e:
        return f"{url}: TLS エラー ({e.reason or type(e).__name__})"
    except ConnectionRefusedError:
        return f"{url} ({ip}:{port}): 接続を拒否されました"
    except (TimeoutError, socket.timeout):
        return f"{url} ({ip}:{port}): タイムアウト"
    except OSError as e:
        return f"{url} ({ip}:{port}): 失敗 ({e.strerror or type(e).__name__})"
    total = (time.monotonic() - t0) * 1000
    lines = head.split(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    keep = ("server", "location", "content-type", "content-length")
    hdrs = [h for h in lines[1:] if h.split(":", 1)[0].lower() in keep]
    out = [f"{url} ({ip}:{port})", f"  {lines[0] or '(応答なし)'}",
           f"  接続 {t_conn:.0f} ms" + (f", TLS まで {t_tls:.0f} ms" if u.scheme == "https" else "")
           + f", 応答まで {total:.0f} ms"]
    out += [f"  {h[:200]}" for h in hdrs]
    return "\n".join(out)


NETPROBE_URL = os.environ.get("NETPROBE_URL", "")


def vlan_probe(vlan: int, check: str, target: str, port: int = 0, count: int = 4,
               record_type: str = "A", server: str = "") -> str:
    """VLAN (DJ=10、AV=20) につないだ検証用コンテナ netprobe から、診断のパケットを出す。ping などの
    ツールは Pod のネットワークから出るが、これは VLAN の機器と同じ側から出るので、「VLAN からつながらない」
    「FortiGate のポリシーで止まっていないか」「VLAN の DHCP / DNS は生きているか」の切り分けに使う。

    Args:
        vlan: 10 (DJ) か 20 (AV)。
        check: ping / arping (同じ VLAN の機器の MAC を ARP で確かめる) / traceroute / dns / tcp / http。
        target: 宛先の IP アドレスかホスト名。http のときは URL。dns のときは引く名前。名前は VLAN の DNS で引く。
        port: tcp のときのポート番号 (22, 53, 80, 443, 445, 2049, 8000, 8080, 8443 など)。
        count: ping と arping の回数 (1〜10)。
        record_type: dns のときの種類 (A, AAAA, CNAME, MX, NS, TXT, PTR, SRV)。
        server: dns のとき問い合わせる DNS サーバーの IP。空なら VLAN のゲートウェイ (FortiGate)。
    """
    if not NETPROBE_URL:
        return "VLAN 側からの診断は設定されていません (NETPROBE_URL が未設定)。"
    body = json.dumps({"vlan": int(vlan), "check": check, "target": target, "port": int(port),
                       "count": int(count), "record_type": record_type, "server": server}).encode()
    req = urllib.request.Request(NETPROBE_URL.rstrip("/") + "/v1/probe", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return json.load(r)["result"]
    except urllib.error.HTTPError as e:
        try:
            detail = json.load(e).get("detail", "")
        except ValueError:
            detail = ""
        raise ValueError(f"netprobe のエラー ({e.code}): {detail}") from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise ValueError(f"netprobe に届きませんでした ({type(e).__name__})。Pod が起動しているか確認する。") from e


NET_TOOLS = [ping, dns_lookup, tcp_check, http_check, vlan_probe]
