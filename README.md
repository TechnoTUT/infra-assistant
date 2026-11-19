# infra-assistant

TechnoTUT のインフラについて、Gemini API のモデル (`gemini-3.8-flash`) が日本語で答える Web チャットです。
クラスタは ServiceAccount で読みます。変更は、画面の承認ボタンを押したときだけ (Pod の再作成、rollout restart、CronJob の手動実行、Argo CD の Refresh / Sync)。リポジトリは git-sync が取り込んだものを読みます。

- 使い方: [https://network.technotut.net/service/aichat](https://network.technotut.net/service/aichat)
- 仕組みと運用: [https://network.technotut.net/computing/aichat](https://network.technotut.net/computing/aichat)
- マニフェスト: [k8s/manifest/aichat/](https://github.com/TechnoTUT/Infra/tree/main/k8s/manifest/aichat) (Infra リポジトリ。イメージは `ghcr.io/technotut/infra-assistant`)

| ファイル | 内容 |
| --- | --- |
| `app/main.py` | API (ジョブの作成とポーリング) と Gemini とのやりとり |
| `app/netdiag.py` | ネットワーク診断のツール (ping、DNS、TCP、HTTP) |
| `netprobe/` | VLAN (VXLAN) につないで診断のパケットを出す検証用コンテナ (別イメージ `netprobe`) |
| `app/healthcheck.py` | 定期のヘルスチェック (LLM を使わない。CronJob で動かし、問題を Discord に通知) |
| `app/tools.py` | Gemini に渡すツールと、承認された操作の実行 |
| `app/prompt.py` | システムプロンプト |
| `app/static/index.html` | チャットの画面 |

## 手元で動かす
```bash
uv sync
GEMINI_API_KEY=<キー> REPO_DIR=<Infra の clone> uv run uvicorn app.main:app --reload
```
