"""Gemini に渡す FortiGate の読み取りツール。ここにある関数の docstring が、そのままツールの説明になる。

読み取り専用 (app/fortigate.py)。DHCP リース、ポリシーとヒット数、インターフェース、経路、負荷。
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import fortigate as fg

MAX_CHARS = 12000


def _cut(text: str) -> str:
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS] + f"\n... (長いので {len(text) - MAX_CHARS} 文字を省略)"


def _when(ts) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(int(ts), timezone.utc).astimezone().strftime("%m-%d %H:%M")


def _names(v) -> str:
    return ",".join(x.get("name", "?") if isinstance(x, dict) else str(x) for x in (v or []))


def _need() -> None:
    if not fg.configured():
        raise ValueError("FortiGate の読み取りは設定されていません (FORTIGATE_TOKEN が未設定)。")


def fortigate_overview() -> str:
    """FortiGate (ファイアウォール) の全体の状態を返す。ファームウェア、CPU とメモリの使用率、セッション数、
    リンクが落ちているインターフェース。「ネットワークの調子は?」「FortiGate は重くない?」のときに最初に呼ぶ。"""
    _need()
    out = []
    try:
        fw = (fg.get("monitor", "system/firmware") or {}).get("current", {})
        out.append(f"ファームウェア: {fw.get('name', 'FortiOS')} {fw.get('version', '?')} build{fw.get('build', '?')}")
    except fg.FortiGateError as e:
        out.append(f"ファームウェア: 取得できません ({e})")
    try:
        u = fg.get("monitor", "system/resource/usage") or {}
        cur = lambda k: fg.current(u, k) if fg.current(u, k) is not None else "?"  # noqa: E731
        out.append(f"CPU {cur('cpu')}% / メモリ {cur('mem')}% / セッション {cur('session')} / 新規セッション {cur('setuprate')}/秒")
    except fg.FortiGateError as e:
        out.append(f"負荷: 取得できません ({e})")
    try:
        down = [n for n, i in (fg.get("monitor", "system/interface") or {}).items()
                if i.get("link") is False and i.get("type") not in ("tunnel",)]
        out.append("リンクが落ちているインターフェース: " + (", ".join(sorted(down)) or "なし"))
    except fg.FortiGateError as e:
        out.append(f"インターフェース: 取得できません ({e})")
    return "\n".join(out)


def fortigate_interfaces(name: str = "") -> str:
    """FortiGate のインターフェースの状態 (リンク、速度、送受信バイト、エラー数) を返す。

    Args:
        name: 名前の一部 (例: po1, dmz, port9)。空なら全て。
    """
    _need()
    rows = []
    for n, i in sorted((fg.get("monitor", "system/interface") or {}).items()):
        if name and name.lower() not in n.lower():
            continue
        rows.append(f"{n}: link={'up' if i.get('link') else 'down'} speed={i.get('speed', '-')} ip={i.get('ip', '-')}/{i.get('mask', '-')}"
                    f" rx={i.get('rx_bytes', '-')}B tx={i.get('tx_bytes', '-')}B rx_err={i.get('rx_errors', '-')} tx_err={i.get('tx_errors', '-')}")
    return _cut("\n".join(rows) or "該当するインターフェースがありません。(sw10 などの software switch は、ここには出ません。ポリシーや DHCP の側で見る)")


def fortigate_dhcp_leases(search: str = "") -> str:
    """FortiGate の DHCP のリース (どの機器にどの IP を貸しているか) を返す。「この IP / MAC は誰?」「機器が
    VLAN にいるか」に使う。

    Args:
        search: IP、MAC、ホスト名、インターフェース名 (sw10、mgmt など) の一部。空なら全て。
    """
    _need()
    q = search.lower().strip()
    rows = []
    for l in fg.get("monitor", "system/dhcp") or []:
        line = (f"{l.get('ip')}  {l.get('mac')}  {l.get('hostname') or '-'}  {l.get('interface')}  "
                f"{l.get('status')}  期限 {_when(l.get('expire_time'))}")
        if not q or q in line.lower():
            rows.append(line)
    return _cut(f"{len(rows)} 件\n" + "\n".join(rows[:150]) if rows else "該当するリースがありません。")


def fortigate_policies(search: str = "") -> str:
    """FortiGate のファイアウォールポリシーを、ヒット数と最後に使われた時刻つきで返す。「どのポリシーで止まる?」
    「このポリシーは使われている?」に使う。許可が必要な通信の有無は、ここで確かめる。

    Args:
        search: 名前、コメント、インターフェース、アドレス、サービスの一部 (例: sw20, plmux, VLAN44 subnet)。空なら全て。
    """
    _need()
    hits = {h["policyid"]: h for h in fg.get("monitor", "firewall/policy") or []}
    q = search.lower().strip()
    rows = []
    for p in fg.get("cmdb", "firewall/policy") or []:
        h = hits.get(p.get("policyid"), {})
        line = (f"[{p.get('policyid')}] {p.get('name') or '-'}: {_names(p.get('srcintf'))}/{_names(p.get('srcaddr'))} -> "
                f"{_names(p.get('dstintf'))}/{_names(p.get('dstaddr'))} svc={_names(p.get('service'))} {p.get('action')}"
                f"{'' if p.get('status', 'enable') == 'enable' else ' (無効)'} hit={h.get('hit_count', 0) if h else '-'} "
                f"最終 {_when(h.get('last_used'))}" + (f" #{p['comments']}" if p.get("comments") else ""))
        if not q or q in line.lower():
            rows.append(line)
    return _cut(f"{len(rows)} 件\n" + "\n".join(rows) if rows else "該当するポリシーがありません。")


def fortigate_routes(search: str = "") -> str:
    """FortiGate の経路表 (IPv4) を返す。「この宛先はどこへ向かう?」に使う。

    Args:
        search: 宛先、ゲートウェイ、インターフェースの一部 (例: 10.10, wan1)。空なら全て。
    """
    _need()
    q = search.lower().strip()
    rows = []
    for r in fg.get("monitor", "router/ipv4") or []:
        line = (f"{r.get('ip_mask')} via {r.get('gateway') or '直結'} dev {r.get('interface')} "
                f"({r.get('type')}, 距離 {r.get('distance')})")
        if not q or q in line.lower():
            rows.append(line)
    return _cut("\n".join(rows) or "該当する経路がありません。")


FG_TOOLS = [fortigate_overview, fortigate_interfaces, fortigate_dhcp_leases, fortigate_policies, fortigate_routes]
