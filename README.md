# infra-assistant

A web chat that answers questions about TechnoTUT's infrastructure in Japanese, using a Gemini API model (`gemini-3.8-flash`). It inspects the Kubernetes cluster, the FortiGate and the network, and reads the [TechnoTUT/Infra](https://github.com/TechnoTUT/Infra) repository (docs and manifests, synced by git-sync).

The repository also holds the jobs that watch the infrastructure around the chat. Those jobs never call an LLM.

- Read-only by default: the cluster is read through a read-only ServiceAccount, and the FortiGate through a read-only API user.
- Changes happen only after a person presses the approve button in the UI: restarting a Pod, a rollout restart, running a CronJob by hand, an Argo CD refresh or sync, and cordon or uncordon of a node.
- The Gemini API is on the paid tier. Questions and cluster information are sent to an external service, so the chat is not allowed to read Secrets.

The documentation lives in the Infra repository and is written in Japanese:

- User guide: <https://network.technotut.net/service/aichat>
- Implementation and operations: <https://network.technotut.net/computing/aichat>
- Monitoring and notifications: <https://network.technotut.net/computing/monitoring>
- Manifests: [k8s/manifest/aichat/](https://github.com/TechnoTUT/Infra/tree/main/k8s/manifest/aichat) (image `ghcr.io/technotut/infra-assistant`), [aichat-rbac/](https://github.com/TechnoTUT/Infra/tree/main/k8s/manifest/aichat-rbac) and [netprobe/](https://github.com/TechnoTUT/Infra/tree/main/k8s/manifest/netprobe)

## Layout

### The chat (a Deployment)

| File | Purpose |
| --- | --- |
| `app/main.py` | HTTP API (job creation and polling, approve and reject endpoints) and the conversation with Gemini |
| `app/tools.py` | Tools given to Gemini (cluster, repository, `propose_action`, `report_issue`) and the execution of approved actions |
| `app/netdiag.py` | Network diagnostics (ping, DNS, TCP, HTTP from the Pod) and `vlan_probe`, which starts a `netprobe` Pod on demand |
| `app/fortigate.py` | Read-only FortiGate REST client (GET only, allowlisted paths) |
| `app/fgtools.py` | FortiGate tools for the chat (policies with hit counts, DHCP leases, routes, interfaces, load) |
| `app/discord.py` | Discord webhook helper (mentions disabled) |
| `app/prompt.py` | System prompt |
| `app/static/index.html` | Chat UI, including the approve button |

### Monitoring jobs (no LLM)

They run from the same image with a different command.

| File | Run as | Purpose |
| --- | --- | --- |
| `app/healthcheck.py` | CronJob, every 5 minutes | Checks nodes, Pods, PVCs, LoadBalancer Services, Argo CD apps, failed CronJobs, DNS and HTTP from inside a Pod, FortiGate reachability and load, and node drift. Notifies Discord when the state changes (new problem, escalation, recovery). |
| `app/nodecheck.py` | DaemonSet | Serves facts about each node (`resolv.conf`, USB serial devices, free disk) read from read-only mounts of the host's `/etc` and `/dev`. `healthcheck` judges them. |
| `app/fgtsnapshot.py` | CronJob, every 5 minutes | Snapshots the main FortiGate configuration tables through the read-only API and reports differences to Discord. |

### netprobe (a separate image)

`netprobe/` is a small API that sends diagnostic packets (ping, arping, traceroute, DNS, TCP, HTTP) from inside a VLAN. It is attached to a VLAN through vxlan-cni and uses per-VLAN policy routing. The chat starts it on demand, and it is deleted a few minutes after use. See `netprobe/Containerfile` and `netprobe/app/main.py`.

## Run locally

```bash
uv sync
GEMINI_API_KEY=<key> REPO_DIR=<path to a clone of the Infra repository> uv run uvicorn app.main:app --reload
```

Open <http://localhost:8000>. The cluster is reached with your local kubeconfig. The FortiGate, Discord and netprobe features are disabled unless their environment variables are set.

| Variable | Meaning |
| --- | --- |
| `GEMINI_API_KEY` | Gemini API key (required) |
| `GEMINI_MODEL` | Model name (default `gemini-3.8-flash`) |
| `REPO_DIR` | Path of the Infra repository that the chat reads |
| `MAX_CONCURRENT` | Number of questions processed at the same time |
| `DISCORD_WEBHOOK_URL` | Discord webhook for reports, approvals and notifications |
| `FORTIGATE_TOKEN` | Token of the read-only FortiGate API user |
| `NETPROBE_IMAGE` | Image of the on-demand netprobe Pod (empty disables `vlan_probe`) |
| `APPROVER_CIDRS` | Comma-separated CIDRs that may approve actions (empty means no restriction) |

The monitoring jobs can be tried without side effects (no notification, no state saved):

```bash
DRY_RUN=1 uv run python -m app.healthcheck
DRY_RUN=1 uv run python -m app.fgtsnapshot
```

## Build

Both images are built by GitHub Actions (`.github/workflows/image.yaml`) and pushed to `ghcr.io/technotut/infra-assistant` and `ghcr.io/technotut/netprobe`. `main` gets the tags `main` and `sha-<commit>`; pull requests only build. The monitoring jobs in the Infra repository pin `sha-<commit>`, so update those tags when the jobs change.
