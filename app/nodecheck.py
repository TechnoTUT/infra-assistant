"""ノードの状態を JSON で返す、小さな HTTP サーバー (DaemonSet で全ノードに置く)。LLM は使わない。

ホストの /etc と /dev を読み取り専用でマウントして、設定のズレ (resolv.conf が空など) を見えるようにする。
判定は healthcheck が行う (ここは事実を返すだけ)。GET /status、GET /healthz。
"""

from __future__ import annotations

import glob
import json
import os
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.environ.get("HOST_ROOT", "/host")
NODE = os.environ.get("NODE_NAME", "?")


def resolv_nameservers() -> list[str]:
    try:
        with open(f"{HOST}/etc/resolv.conf") as f:
            return [l.split()[1] for l in f if l.startswith("nameserver") and len(l.split()) > 1]
    except OSError:
        return []


def status() -> dict:
    usage = shutil.disk_usage(f"{HOST}/etc")
    devices = sorted("/" + os.path.relpath(p, HOST)
                     for p in glob.glob(f"{HOST}/dev/ttyUSB*") + glob.glob(f"{HOST}/dev/ttyACM*"))
    try:
        load1 = os.getloadavg()[0]
    except OSError:
        load1 = None
    return {"node": NODE, "resolv_nameservers": resolv_nameservers(), "devices": devices,
            "disk_free_percent": round(usage.free * 100 / usage.total, 1), "load1": load1}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            body, code = b'{"ok": true}', 200
        elif self.path == "/status":
            body, code = json.dumps(status()).encode(), 200
        else:
            body, code = b'{"error": "not found"}', 404
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # アクセスログは出さない
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9100), Handler).serve_forever()
