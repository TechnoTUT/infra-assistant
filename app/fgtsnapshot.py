"""FortiGate の設定のスナップショットと、変更の検知。LLM は使わない。CronJob で `python -m app.fgtsnapshot`。

設定ファイルの取得 (backup) にはメンテナンス権限が要るので使わず、読み取りの API で主要な設定のテーブルを取って、
JSON にして ConfigMap `fortigate-snapshot` に持つ (gzip)。前回との差を Discord に知らせる。最初の実行は基準を作るだけ。
手で変えられた設定や、fortigate-operator による変更が、いつ何に変わったかが分かる。
"""

from __future__ import annotations

import base64
import gzip
import json
import os
import sys

from kubernetes import client, config
from kubernetes.client import ApiException

from . import discord, fortigate as fg

NAMESPACE = os.environ.get("POD_NAMESPACE", "aichat")
SNAPSHOT_NAME = "fortigate-snapshot"
DRY_RUN = os.environ.get("DRY_RUN", "") not in ("", "0", "false")
# (cmdb の path, 識別に使うキー)。管理者、API ユーザー、証明書などの秘密に近いものは入れない
TABLES = [("firewall/policy", "policyid"), ("firewall/address", "name"), ("firewall.service/custom", "name"),
          ("system/interface", "name"), ("system/vxlan", "name"), ("system/switch-interface", "name"),
          ("system.dhcp/server", "id"), ("system/dns-server", "name"), ("system/dns-database", "name"),
          ("router/static", "seq-num")]
MASK = ("password", "passwd", "secret", "key", "psk", "token")
MAX_LINES = 40


def take() -> dict:
    snap = {}
    for path, key in TABLES:
        rows = fg.get("cmdb", path, timeout=40) or []
        snap[path] = {str(r.get(key, r.get("q_origin_key"))): _clean(r) for r in rows}
    return snap


def _clean(row: dict) -> dict:
    return {k: ("[伏せました]" if any(m in k.lower() for m in MASK) else v)
            for k, v in row.items() if k != "q_origin_key"}


def _short(v) -> str:
    if isinstance(v, list):
        v = [x.get("name", x) if isinstance(x, dict) and "name" in x else x for x in v]
    s = json.dumps(v, ensure_ascii=False) if not isinstance(v, str) else v
    return s if len(s) <= 120 else s[:120] + "…"


def diff(old: dict, new: dict) -> list[str]:
    lines = []
    for path, _ in TABLES:
        o, n = old.get(path, {}), new.get(path, {})
        for k in n.keys() - o.keys():
            lines.append(f"+ {path} [{k}] を追加" + (f" ({n[k].get('name')})" if n[k].get("name") and path != 'system/interface' else ""))
        for k in o.keys() - n.keys():
            lines.append(f"- {path} [{k}] を削除")
        for k in sorted(o.keys() & n.keys()):
            for f in sorted(set(o[k]) | set(n[k])):
                if o[k].get(f) != n[k].get(f):
                    lines.append(f"~ {path} [{k}] {f}: {_short(o[k].get(f))} → {_short(n[k].get(f))}")
    return lines


def load(core) -> dict | None:
    try:
        cm = core.read_namespaced_config_map(SNAPSHOT_NAME, NAMESPACE)
    except ApiException as e:
        if e.status == 404:
            return None
        raise
    return json.loads(gzip.decompress(base64.b64decode(cm.binary_data["snapshot"])))


def save(core, snap: dict) -> None:
    data = base64.b64encode(gzip.compress(json.dumps(snap, ensure_ascii=False).encode())).decode()
    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=SNAPSHOT_NAME, namespace=NAMESPACE), binary_data={"snapshot": data})
    try:
        core.replace_namespaced_config_map(SNAPSHOT_NAME, NAMESPACE, body)
    except ApiException as e:
        if e.status != 404:
            raise
        core.create_namespaced_config_map(NAMESPACE, body)


def main() -> int:
    try:
        new = take()
    except fg.FortiGateError as e:
        print(f"snapshot failed: {e}", file=sys.stderr)
        return 1
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    core = client.CoreV1Api()
    old = load(core)
    if old is None:
        print("基準のスナップショットを作りました (通知なし)")
        if not DRY_RUN:
            save(core, new)
        return 0
    lines = diff(old, new)
    print(f"変更 {len(lines)} 件")
    for l in lines[:MAX_LINES]:
        print(l)
    if lines and not DRY_RUN:
        text = "\n".join(lines[:MAX_LINES]) + (f"\n… ほか {len(lines) - MAX_LINES} 件" if len(lines) > MAX_LINES else "")
        if not discord.post([{"title": f"[情報] FortiGate の設定が変わりました ({len(lines)} 件)", "color": 0x3B82F6,
                              "description": f"```\n{text[:3800]}\n```",
                              "footer": {"text": "infra-assistant (読み取りの API の差分。fortigate-operator の変更も含む)"}}], wait=True):
            print("通知できなかったため、基準を更新しません (次回、もう一度通知)", file=sys.stderr)
            return 1 if discord.WEBHOOK else (save(core, new) or 0)
    if not DRY_RUN:
        save(core, new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
