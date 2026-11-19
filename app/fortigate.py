"""FortiGate の REST API (読み取り専用) のクライアント。GET だけ、許可した path だけ。

トークンは Secret fortigate-readonly (FortiGate の API ユーザー infra-readonly、読み取り専用のプロファイル、
trusthost は dmz の 192.168.99.128/25)。API は dmz のホストからしか届かない。Pod の通信はノードの IP に NAT される。
自己署名の証明書なので、固定の IP (192.168.99.129) に限って検証を省く。
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("FORTIGATE_URL", "https://192.168.99.129")
TOKEN = os.environ.get("FORTIGATE_TOKEN", "")
# 読んでよいもの。設定ファイルの取得 (backup)、管理者、API ユーザー、証明書や鍵は含めない
ALLOWED = {
    "monitor": {"system/status", "system/interface", "system/dhcp", "system/resource/usage", "system/firmware",
                "firewall/policy", "router/ipv4"},
    "cmdb": {"firewall/policy", "firewall/address", "firewall.service/custom", "system/interface", "system/vxlan",
             "system/switch-interface", "system/dns-server", "system/dns-database", "system.dhcp/server",
             "router/static"},
}
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


class FortiGateError(Exception):
    pass


def configured() -> bool:
    return bool(TOKEN)


def get(kind: str, path: str, params: dict | None = None, timeout: int = 20):
    """results を返す。許可していない path と、API のエラーは FortiGateError。"""
    if kind not in ALLOWED or path not in ALLOWED[kind]:
        raise FortiGateError(f"{kind}/{path} は読めません。")
    if not TOKEN:
        raise FortiGateError("FortiGate の API トークンが設定されていません (FORTIGATE_TOKEN)。")
    url = f"{BASE}/api/v2/{kind}/{path}" + (("?" + urllib.parse.urlencode(params)) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            return json.load(r).get("results")
    except urllib.error.HTTPError as e:
        raise FortiGateError(f"FortiGate API のエラー ({e.code})") from e
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise FortiGateError(f"FortiGate API に届きません ({type(e).__name__})") from e
