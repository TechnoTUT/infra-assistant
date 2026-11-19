# infra-assistant

TechnoTUT のインフラについて、Gemini API のモデル (`gemini-3.8-flash`) が日本語で答える Web チャットです。
クラスタは読み取り専用の ServiceAccount で読み、リポジトリは git-sync が取り込んだものを読みます。

- 使い方: [https://network.technotut.net/service/aichat](https://network.technotut.net/service/aichat)
- 仕組みと運用: [https://network.technotut.net/computing/aichat](https://network.technotut.net/computing/aichat)
- マニフェスト: [k8s/manifest/aichat/](https://github.com/TechnoTUT/Infra/tree/main/k8s/manifest/aichat) (Infra リポジトリ。イメージは `ghcr.io/technotut/infra-assistant`)

| ファイル | 内容 |
| --- | --- |
| `app/main.py` | API (ジョブの作成とポーリング) と Gemini とのやりとり |
| `app/tools.py` | Gemini に渡すツール (クラスタとリポジトリの読み取り) |
| `app/prompt.py` | システムプロンプト |
| `app/static/index.html` | チャットの画面 |

## 手元で動かす
```bash
uv sync
GEMINI_API_KEY=<キー> REPO_DIR=<Infra の clone> uv run uvicorn app.main:app --reload
```
