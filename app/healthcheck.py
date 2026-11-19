"""定期のヘルスチェック。LLM は使わず、Kubernetes API などを直接見て、悪い状態が続いたら Discord に知らせる。

CronJob で `python -m app.healthcheck` を 5 分ごとに動かす。状態 (いつから悪いか、通知したか) は ConfigMap に持つ。
通知は 1 回の実行につき 1 メッセージ (新しい問題と復旧をまとめる)。同じ問題は、復旧するまで再通知しない。
DRY_RUN=1 なら、見つけた問題を標準出力に出すだけで、通知も状態の保存もしない。
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone

from kubernetes import client, config
from kubernetes.client import ApiException

WEBHOOK = os.environ.get("DISCORD_WEBHOOK_URL", "")
NAMESPACE = os.environ.get("POD_NAMESPACE", "aichat")
STATE_NAME = "healthcheck-state"
DRY_RUN = os.environ.get("DRY_RUN", "") not in ("", "0", "false")
# アラームは、解除 (復旧) されるまで再通知しない。再通知したいときだけ秒数を入れる (0 = しない)
RENOTIFY = int(os.environ.get("RENOTIFY_SECONDS", "0"))
# 一時的な状態 (起動中、同期中) を拾わないよう、問題ごとに「これだけ続いたら通知する」を決める (秒)
AGE_NODE = int(os.environ.get("AGE_NODE", "120"))
AGE_POD = int(os.environ.get("AGE_POD", "300"))
AGE_APP = int(os.environ.get("AGE_APP", "600"))
AGE_NET = int(os.environ.get("AGE_NET", "120"))
CRASH_REASONS = {"CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
                 "CreateContainerError", "InvalidImageName", "RunContainerError"}
# 名前が引けるか確かめる (Pod の DNS = CoreDNS 経由。外部の名前と、FortiGate が答える内部の名前)
DNS_NAMES = [n for n in os.environ.get("DNS_NAMES", "github.com,ai.svc.technotut.net").split(",") if n]
HTTP_URLS = [u for u in os.environ.get("HTTP_URLS", "https://github.com").split(",") if u]
# ノードの検査 (DaemonSet nodecheck が返す事実を、ここで判定する)
EXPECT_DNS = [n for n in os.environ.get("EXPECT_NODE_DNS", "").split(",") if n]       # 空なら見ない
EXPECT_DEVICES = dict(p.split("=", 1) for p in os.environ.get("EXPECT_NODE_DEVICES", "").split(";") if "=" in p)
MIN_DISK_FREE = float(os.environ.get("MIN_DISK_FREE_PERCENT", "10"))
SEVERITY = {"warning": (0xF59E0B, "警告"), "critical": (0xC7000A, "重大")}


@dataclass
class Issue:
    key: str
    severity: str
    title: str
    detail: str
    min_age: int
    since: datetime | None = None   # わかるときは、その状態になった時刻 (わからなければ、最初に見た時刻を使う)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(s) -> datetime | None:
    if not s:
        return None
    if isinstance(s, datetime):
        return s if s.tzinfo else s.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def _workload(pod) -> str:
    """Pod の名前は作り直すたびに変わるので、持ち主 (Deployment など) の名前で問題をまとめる。"""
    owners = pod.metadata.owner_references or []
    if not owners:
        return pod.metadata.name
    o = owners[0]
    return o.name.rsplit("-", 1)[0] if o.kind == "ReplicaSet" else o.name


# ---- チェック ----

def check_nodes(core) -> list[Issue]:
    out = []
    for n in core.list_node().items:
        ready = next((c for c in n.status.conditions or [] if c.type == "Ready"), None)
        if ready is None or ready.status != "True":
            out.append(Issue(f"node:{n.metadata.name}", "critical", f"ノード {n.metadata.name} が NotReady",
                             f"Ready={ready.status if ready else '?'} ({ready.reason if ready else '-'})",
                             AGE_NODE, _ts(ready.last_transition_time) if ready else None))
        for c in n.status.conditions or []:
            if c.type in ("MemoryPressure", "DiskPressure", "PIDPressure") and c.status == "True":
                out.append(Issue(f"node:{n.metadata.name}:{c.type}", "warning",
                                 f"ノード {n.metadata.name} が {c.type}", c.message or "", AGE_NODE,
                                 _ts(c.last_transition_time)))
    return out


def check_pods(core) -> list[Issue]:
    out: dict[str, Issue] = {}
    for p in core.list_pod_for_all_namespaces().items:
        ns, st = p.metadata.namespace, p.status
        wl = _workload(p)
        if st.phase in ("Succeeded",):
            continue
        reason = None
        for c in (st.container_statuses or []) + (st.init_container_statuses or []):
            w = c.state.waiting if c.state else None
            if w and w.reason in CRASH_REASONS:
                reason = f"{w.reason} ({c.name}): {(w.message or '')[:200]}"
        if reason:
            out[f"pod:{ns}/{wl}:crash"] = Issue(f"pod:{ns}/{wl}:crash", "critical",
                                                f"{ns}/{wl} の Pod が起動を繰り返し失敗", reason, AGE_POD)
        elif st.phase == "Pending" or (st.phase == "Running" and any(
                not c.ready for c in st.container_statuses or [])):
            if p.metadata.deletion_timestamp:
                continue
            msg = next((c.message for c in st.conditions or [] if c.status == "False" and c.message), "")
            what = "Pending" if st.phase == "Pending" else "Ready にならない"
            out.setdefault(f"pod:{ns}/{wl}:notready", Issue(
                f"pod:{ns}/{wl}:notready", "warning", f"{ns}/{wl} の Pod が {what}",
                f"{p.metadata.name} ({st.phase}) {msg}"[:300], AGE_POD, _ts(p.metadata.creation_timestamp)))
        elif st.phase == "Failed" and not p.metadata.owner_references:
            out[f"pod:{ns}/{wl}:failed"] = Issue(f"pod:{ns}/{wl}:failed", "warning",
                                                 f"{ns}/{wl} の Pod が Failed ({st.reason})", st.message or "", AGE_POD)
    return list(out.values())


def check_pvcs(core) -> list[Issue]:
    return [Issue(f"pvc:{p.metadata.namespace}/{p.metadata.name}", "warning",
                  f"PVC {p.metadata.namespace}/{p.metadata.name} が Pending", "ストレージが割り当てられていません",
                  AGE_POD, _ts(p.metadata.creation_timestamp))
            for p in core.list_persistent_volume_claim_for_all_namespaces().items if p.status.phase == "Pending"]


def check_lb(core) -> list[Issue]:
    out = []
    for s in core.list_service_for_all_namespaces().items:
        if s.spec.type == "LoadBalancer" and not (s.status.load_balancer and s.status.load_balancer.ingress):
            out.append(Issue(f"svc:{s.metadata.namespace}/{s.metadata.name}", "warning",
                             f"Service {s.metadata.namespace}/{s.metadata.name} に LB の IP が付かない",
                             "LoadBalancer の IP プールか BGP を確認", AGE_POD, _ts(s.metadata.creation_timestamp)))
    return out


def check_argocd(custom) -> list[Issue]:
    out = []
    try:
        apps = custom.list_namespaced_custom_object("argoproj.io", "v1alpha1", "argocd", "applications")["items"]
    except ApiException as e:
        return [Issue("argocd:api", "warning", "Argo CD のアプリを読めない", f"{e.status} {e.reason}", AGE_NET)]
    for a in apps:
        name, st = a["metadata"]["name"], a.get("status", {})
        health = (st.get("health") or {})
        sync = (st.get("sync") or {})
        if health.get("status") not in (None, "Healthy", "Progressing"):
            out.append(Issue(f"app:{name}:health", "critical" if health["status"] == "Degraded" else "warning",
                             f"Argo CD アプリ {name} が {health['status']}", health.get("message", "") or "", AGE_APP,
                             _ts(health.get("lastTransitionTime"))))
        if sync.get("status") == "OutOfSync":
            out.append(Issue(f"app:{name}:sync", "warning", f"Argo CD アプリ {name} が OutOfSync",
                             "Git との同期ができていません", AGE_APP))
        cond = [c for c in st.get("conditions") or [] if "Error" in c.get("type", "")]
        for c in cond:
            out.append(Issue(f"app:{name}:{c['type']}", "warning", f"Argo CD アプリ {name}: {c['type']}",
                             (c.get("message") or "")[:300], AGE_APP, _ts(c.get("lastTransitionTime"))))
    return out


def check_nodes_detail(core) -> list[Issue]:
    """全ノードの nodecheck に聞いて、設定のズレ (resolv.conf、USB デバイス、ディスク) を見つける。"""
    out = []
    pods = core.list_namespaced_pod(NAMESPACE, label_selector="app=nodecheck").items
    for p in pods:
        node = p.spec.node_name or p.metadata.name
        if not p.status.pod_ip or p.status.phase != "Running":
            continue   # Pod が動いていないことは check_pods が見る
        try:
            with urllib.request.urlopen(f"http://{p.status.pod_ip}:9100/status", timeout=5) as r:
                st = json.load(r)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            out.append(Issue(f"nodecheck:{node}:unreachable", "warning", f"ノード {node} の nodecheck に届かない",
                             type(e).__name__, AGE_POD))
            continue
        if EXPECT_DNS and st["resolv_nameservers"] != EXPECT_DNS:
            out.append(Issue(f"node:{node}:resolv", "critical", f"ノード {node} の DNS 設定がずれている",
                             f"/etc/resolv.conf の nameserver = {st['resolv_nameservers'] or '(なし)'}、期待は {EXPECT_DNS}。"
                             "Ansible の common ロールで固定している", AGE_NET))
        for dev in [d for d in EXPECT_DEVICES.get(node, "").split(",") if d]:
            if dev not in st["devices"]:
                out.append(Issue(f"node:{node}:device:{dev}", "warning", f"ノード {node} に {dev} がない",
                                 f"USB デバイスが認識されていません (認識中: {st['devices'] or 'なし'})", AGE_POD))
        if st["disk_free_percent"] < MIN_DISK_FREE:
            out.append(Issue(f"node:{node}:disk", "warning", f"ノード {node} のディスクの空きが少ない",
                             f"空き {st['disk_free_percent']}% (しきい値 {MIN_DISK_FREE}%)", AGE_POD))
    return out


def check_cronjobs() -> list[Issue]:
    """CronJob の直近に終わった Job が失敗していて、その後に一度も成功していないものを探す。

    履歴は 1 件に絞ってあり、実行中は直前の成功した Job が消えていることがある。そのため「成功したか」は、
    履歴ではなく CronJob の status.lastSuccessfulTime (履歴を消しても残る) と比べる。"""
    batch = client.BatchV1Api()
    last_ok = {c.metadata.name: _ts(c.status.last_successful_time) for c in batch.list_namespaced_cron_job(NAMESPACE).items}
    failed: dict[str, tuple[datetime, str]] = {}
    for j in batch.list_namespaced_job(NAMESPACE).items:
        owner = next((o.name for o in j.metadata.owner_references or [] if o.kind == "CronJob"), None)
        f = next((c for c in j.status.conditions or [] if c.type == "Failed" and c.status == "True"), None)
        if not owner or not f:
            continue
        t = _ts(f.last_transition_time) or _ts(j.metadata.creation_timestamp)
        if owner not in failed or t > failed[owner][0]:
            failed[owner] = (t, f.message or f.reason or "")
    return [Issue(f"cronjob:{name}", "warning", f"CronJob {name} の直近の実行が失敗", msg[:300], 0, t)
            for name, (t, msg) in failed.items() if not (last_ok.get(name) and last_ok[name] > t)]


def check_fortigate() -> list[Issue]:
    """FortiGate の API に届くか、CPU とメモリが高すぎないか (トークンがなければ見ない)。"""
    from . import fortigate as fg
    if not fg.configured():
        return []
    try:
        u = fg.get("monitor", "system/resource/usage") or {}
    except fg.FortiGateError as e:
        return [Issue("fortigate:api", "warning", "FortiGate の API に届かない", str(e), AGE_NET)]
    out = []
    for key, label in (("cpu", "CPU"), ("mem", "メモリ")):
        cur = fg.current(u, key)
        if isinstance(cur, (int, float)) and cur >= float(os.environ.get("FORTIGATE_MAX_PERCENT", "90")):
            out.append(Issue(f"fortigate:{key}", "warning", f"FortiGate の {label} が高い",
                             f"{label} {cur}% (VXLAN の転送は CPU で処理している)", AGE_POD))
    return out


def check_network() -> list[Issue]:
    out = []
    for name in DNS_NAMES:
        try:
            socket.getaddrinfo(name, None)
        except OSError as e:
            out.append(Issue(f"dns:{name}", "critical", f"名前 {name} を引けない",
                             f"Pod の DNS (CoreDNS) で失敗: {e.strerror or type(e).__name__}。"
                             "ノードの /etc/resolv.conf と CoreDNS の上流を確認", AGE_NET))
    for url in HTTP_URLS:
        try:
            urllib.request.urlopen(urllib.request.Request(url, method="HEAD", headers={"User-Agent": "healthcheck"}),
                                   timeout=10, context=ssl.create_default_context()).close()
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            code = getattr(e, "code", None)
            if code and code < 500:   # 4xx は届いている
                continue
            out.append(Issue(f"http:{url}", "warning", f"{url} に届かない", f"{type(e).__name__}: {getattr(e, 'reason', e)}",
                             AGE_NET))
    return out


def collect(core, custom) -> list[Issue]:
    issues: list[Issue] = []
    for name, fn in (("nodes", lambda: check_nodes(core)), ("pods", lambda: check_pods(core)),
                     ("node-detail", lambda: check_nodes_detail(core)), ("pvcs", lambda: check_pvcs(core)), ("lb", lambda: check_lb(core)),
                     ("argocd", lambda: check_argocd(custom)), ("network", check_network), ("fortigate", check_fortigate), ("cronjobs", check_cronjobs)):
        try:
            issues += fn()
        except ApiException as e:   # チェック自体の失敗は、そのチェックだけ飛ばす (RBAC の不足など)
            print(f"check {name} failed: {e.status} {e.reason}", file=sys.stderr)
            issues.append(Issue(f"check:{name}", "warning", f"ヘルスチェック '{name}' が実行できない",
                                f"{e.status} {e.reason}。ClusterRole を確認", 600))
        except Exception as e:  # noqa: BLE001  想定外の例外でも、ほかのチェックと通知は止めない
            print(f"check {name} crashed: {type(e).__name__}: {e}", file=sys.stderr)
            issues.append(Issue(f"check:{name}", "warning", f"ヘルスチェック '{name}' が例外で止まった",
                                f"{type(e).__name__}: {str(e)[:200]}", 600))
    return issues


# ---- 状態 ----

def load_state(core) -> dict:
    try:
        cm = core.read_namespaced_config_map(STATE_NAME, NAMESPACE)
        return json.loads((cm.data or {}).get("state", "{}"))
    except ApiException as e:
        if e.status == 404:
            return {}
        raise


def save_state(core, state: dict) -> None:
    body = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=STATE_NAME, namespace=NAMESPACE),
                              data={"state": json.dumps(state)})
    try:
        core.replace_namespaced_config_map(STATE_NAME, NAMESPACE, body)
    except ApiException as e:
        if e.status != 404:
            raise
        core.create_namespaced_config_map(NAMESPACE, body)


def decide(issues: list[Issue], state: dict, now: float) -> tuple[list, list, list, dict]:
    """(新しい問題, 続いている問題の再通知, 復旧, 新しい状態)。"""
    new_state, new, again = {}, [], []
    seen = {i.key: i for i in issues}
    for key, i in seen.items():
        s = state.get(key, {})
        first = s.get("first") or (i.since.timestamp() if i.since else now)
        if i.since:
            first = min(first, i.since.timestamp())
        entry = {"first": first, "notified": s.get("notified", 0), "title": i.title}
        if now - first >= i.min_age:
            if not entry["notified"]:
                new.append((i, now - first)); entry["notified"] = now
            elif RENOTIFY and now - entry["notified"] >= RENOTIFY:
                again.append((i, now - first)); entry["notified"] = now
        new_state[key] = entry
    recovered = [(s["title"], now - s["first"]) for k, s in state.items()
                 if k not in seen and s.get("notified")]
    return new, again, recovered, new_state


def _dur(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600} 時間 {sec % 3600 // 60} 分" if sec >= 3600 else f"{sec // 60} 分"


def notify(new, again, recovered) -> None:
    embeds = []
    for label, group in (("新しい問題", new), ("まだ続いている問題", again)):
        for i, age in group[:8]:
            color, jp = SEVERITY[i.severity]
            embeds.append({"title": f"[{jp}] {i.title}", "color": color, "description": i.detail[:900] or "-",
                           "footer": {"text": f"{label} / {_dur(age)} 続いています"}})
    if recovered:
        embeds.append({"title": "復旧", "color": 0x10B981,
                       "description": "\n".join(f"- {t} ({_dur(a)} 続いていた)" for t, a in recovered[:15])})
    if not embeds:
        return
    body = json.dumps({"username": "Infra Healthcheck", "embeds": embeds[:10],
                       "allowed_mentions": {"parse": []}}).encode()
    req = urllib.request.Request(WEBHOOK, data=body, headers={"Content-Type": "application/json",
                                                              "User-Agent": "infra-healthcheck"})
    urllib.request.urlopen(req, timeout=15).read()


def main() -> int:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    core, custom = client.CoreV1Api(), client.CustomObjectsApi()
    issues = collect(core, custom)
    if DRY_RUN:
        for i in issues:
            print(f"[{i.severity}] ({i.min_age}s~) {i.title} | {i.detail}")
        print(f"{len(issues)} 件 (DRY_RUN。通知も状態の保存もしない)")
        return 0
    now = time.time()
    state = load_state(core)
    new, again, recovered, new_state = decide(issues, state, now)
    if (new or again or recovered) and WEBHOOK:
        try:
            notify(new, again, recovered)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            print(f"discord failed: {e}", file=sys.stderr)
            return 1    # 状態を保存しない = 次の実行でもう一度通知する
    elif new or again or recovered:
        print("DISCORD_WEBHOOK_URL が未設定のため、通知しません", file=sys.stderr)
    save_state(core, new_state)
    print(f"issues={len(issues)} new={len(new)} again={len(again)} recovered={len(recovered)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
