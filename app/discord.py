"""Discord の Webhook への通知 (標準ライブラリだけ)。メンションは無効にする。"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request

log = logging.getLogger("aichat")
WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")


def post(embeds: list[dict], username: str = "Infra Assistant", wait: bool = False) -> bool:
    """embeds を送る。URL がなければ何もしない。wait=False なら別スレッドで送り、失敗してもログだけ。"""
    if not WEBHOOK or not embeds:
        return False

    def send() -> bool:
        body = json.dumps({"username": username, "embeds": embeds[:10],
                           "allowed_mentions": {"parse": []}}).encode()
        req = urllib.request.Request(WEBHOOK, data=body, headers={
            "Content-Type": "application/json", "User-Agent": "infra-assistant"})
        try:
            urllib.request.urlopen(req, timeout=10).read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            log.warning("discord failed: %s", e)
            return False

    if wait:
        return send()
    threading.Thread(target=send, daemon=True).start()
    return True
