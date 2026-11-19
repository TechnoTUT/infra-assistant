"""TechnoTUT インフラの AI チャット。Gemini の function calling で、クラスタとリポジトリを読んで答える。

Cilium Ingress (Envoy) のルートは 15 秒で切れるので、1 回の応答を長いリクエストにしない。
POST /api/chat でジョブを作り、ブラウザが GET /api/jobs/{id} を 1 秒ごとに読む。
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import ipaddress

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from google import genai
from google.genai import errors, types
from pydantic import BaseModel, Field

from . import discord
from .prompt import SYSTEM_PROMPT
from .tools import TOOLS, call_tool, execute_action, validate_action

log = logging.getLogger("aichat")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
API_KEY = os.environ.get("GEMINI_API_KEY", "")
MAX_STEPS = int(os.environ.get("MAX_TOOL_STEPS", "10"))  # 1 回の質問でツールを呼ぶ回数の上限
MAX_HISTORY = 20       # モデルに渡す過去のやりとりの数
MAX_MESSAGE = 4000     # 1 つの発言の文字数の上限
JOB_TTL = 600          # 終わったジョブを覚えておく秒数
ACTION_TTL = 600       # 承認待ちの操作を覚えておく秒数 (過ぎたら承認できない)
# レート制限と課金を抑えるため、同時に動かす質問の数を絞る
SLOTS = threading.Semaphore(int(os.environ.get("MAX_CONCURRENT", "2")))

STATIC = Path(__file__).parent / "static"
gemini = genai.Client(api_key=API_KEY) if API_KEY else None
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
# ロゴと favicon (booth-display と同じ TechnoTUT のロゴ)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


class Message(BaseModel):
    role: str = Field(pattern="^(user|model)$")
    text: str = Field(max_length=MAX_MESSAGE * 4)


class ChatRequest(BaseModel):
    history: list[Message] = Field(default_factory=list, max_length=100)
    message: str = Field(min_length=1, max_length=MAX_MESSAGE)


@dataclass
class Job:
    events: list[dict] = field(default_factory=list)
    done: bool = False
    finished_at: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def emit(self, **ev) -> None:
        with self.lock:
            self.events.append(ev)

    def finish(self) -> None:
        with self.lock:
            self.done = True
            self.finished_at = time.time()


JOBS: dict[str, Job] = {}
JOBS_LOCK = threading.Lock()
# 承認待ちの操作。内容はサーバーが持ち、ブラウザは ID だけを送る (内容は差し替えられない)
PENDING: dict[str, tuple[float, dict]] = {}
PENDING_LOCK = threading.Lock()
MAX_PENDING = 50
# 承認できる送信元 (カンマ区切りの CIDR)。空なら制限しない。ログインがないので、送信元の IP で絞る
APPROVER_CIDRS = [ipaddress.ip_network(c.strip()) for c in os.environ.get("APPROVER_CIDRS", "").split(",") if c.strip()]


def _propose(job: Job, args: dict) -> str:
    try:
        a = validate_action(str(args.get("action", "")), str(args.get("name", "")),
                            str(args.get("namespace", "")), str(args.get("kind", "")))
    except ValueError as e:
        return f"エラー: {e}"
    now = time.time()
    with PENDING_LOCK:
        for k in [k for k, (t, _) in PENDING.items() if now - t > ACTION_TTL]:
            del PENDING[k]
        if len(PENDING) >= MAX_PENDING:
            return "エラー: 承認待ちの操作が多すぎます。少し待ってください。"
        action_id = uuid.uuid4().hex
        PENDING[action_id] = (now, a)
    job.emit(type="confirm", id=action_id, **a)
    log.info("proposed %s %s", action_id, a["summary"])
    return ("承認待ちにしました。まだ実行していません。ユーザーが画面の承認ボタンを押したときだけ実行されます。"
            "何をするか、なぜ必要か、起きる影響を説明して答えを終えてください。")


def _gc() -> None:
    now = time.time()
    with JOBS_LOCK:
        for k in [k for k, j in JOBS.items() if j.done and now - j.finished_at > JOB_TTL]:
            del JOBS[k]


def _friendly(e: errors.APIError) -> str:
    if e.code == 429:
        return ("Gemini API のレート制限 (または利用の上限) に達しました。少し待って"
                "もう一度試してください。")
    if e.code in (401, 403) or (e.code == 400 and "API key" in (e.message or "")):
        return "Gemini API キーが正しくないようです。管理者に連絡してください。"
    if e.code == 404:
        return f"モデル {MODEL} が見つかりません。管理者に連絡してください。"
    return f"Gemini API のエラー ({e.code}): {e.message}"


def _run(job: Job, req: ChatRequest) -> None:
    contents: list[types.Content] = [
        types.Content(role=m.role, parts=[types.Part.from_text(text=m.text)])
        for m in req.history[-MAX_HISTORY:]
    ]
    contents.append(types.Content(role="user", parts=[types.Part.from_text(text=req.message)]))
    cfg = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=TOOLS,
        # ツールの呼び出しを画面に出すため、SDK の自動実行は使わずに自分で回す
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    if not SLOTS.acquire(timeout=60):
        job.emit(type="error", text="混み合っています。少し待ってからもう一度試してください。")
        job.finish()
        return
    try:
        for _ in range(MAX_STEPS):
            resp = gemini.models.generate_content(model=MODEL, contents=contents, config=cfg)
            calls = resp.function_calls or []
            if not calls:
                job.emit(type="answer", text=resp.text or "(回答が空でした。質問を言い換えてみてください)")
                return
            contents.append(resp.candidates[0].content)  # thought signature を保つためそのまま戻す
            parts = []
            for fc in calls:
                args = dict(fc.args or {})
                job.emit(type="tool", name=fc.name, args=args)
                log.info("tool %s %s", fc.name, args)
                result = _propose(job, args) if fc.name == "propose_action" else call_tool(fc.name, args)
                parts.append(types.Part.from_function_response(name=fc.name, response={"result": result}))
            # 関数の結果は user の発言として返す (API は user と model の role しか受け付けない)
            contents.append(types.Content(role="user", parts=parts))
        job.emit(type="error", text=f"調べる手順が {MAX_STEPS} 回を超えたので止めました。質問を絞ってみてください。")
    except errors.APIError as e:
        log.warning("gemini error: %s", e)
        job.emit(type="error", text=_friendly(e))
    except Exception as e:  # noqa: BLE001
        log.exception("chat failed")
        job.emit(type="error", text=f"内部エラー: {type(e).__name__}")
    finally:
        SLOTS.release()
        job.finish()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/api/info")
def info() -> dict:
    return {"model": MODEL, "ready": gemini is not None}


@app.post("/api/chat")
def chat(req: ChatRequest) -> dict:
    if gemini is None:
        raise HTTPException(503, "Gemini API キーが設定されていません。管理者に連絡してください。")
    _gc()
    job_id = uuid.uuid4().hex
    job = Job()
    with JOBS_LOCK:
        JOBS[job_id] = job
    threading.Thread(target=_run, args=(job, req), daemon=True).start()
    return {"id": job_id}


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str, after: int = 0) -> dict:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, "ジョブが見つかりません。ページを読み込み直してください。")
    with job.lock:
        return {"events": job.events[after:], "next": len(job.events), "done": job.done}


def _take(action_id: str) -> dict:
    """承認待ちの操作を 1 回だけ取り出す (二重実行を防ぐ)。"""
    with PENDING_LOCK:
        item = PENDING.pop(action_id, None)
    if item is None or time.time() - item[0] > ACTION_TTL:
        raise HTTPException(404, "この操作は期限切れか、すでに処理されています。もう一度質問してください。")
    return item[1]


def _client_ip(request: Request) -> str:
    """送信元の IP。Envoy (Cilium Ingress) が X-Forwarded-For の末尾に本当の送信元を足すので、その末尾を使う。"""
    xff = request.headers.get("x-forwarded-for", "")
    return xff.split(",")[-1].strip() if xff else (request.client.host if request.client else "?")


def _check_approver(ip: str) -> None:
    if not APPROVER_CIDRS:
        return
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(403, "送信元を確認できないため、承認できません。") from None
    if not any(addr in net for net in APPROVER_CIDRS):
        raise HTTPException(403, "この場所からは操作を承認できません。")


def _audit(kind: str, a: dict, ip: str, result: str, ok: bool = True) -> None:
    """承認・却下を Discord に残す (誰かはわからないので、送信元の IP と時刻を残す)。"""
    color = {"approved": 0xF59E0B, "rejected": 0x94A3B8}[kind] if ok else 0xC7000A
    label = {"approved": "承認して実行", "rejected": "却下"}[kind]
    discord.post([{"title": f"[操作] {label}: {a['summary']}", "color": color,
                   "fields": [{"name": "結果", "value": result[:900] or "-"},
                              {"name": "送信元", "value": ip}],
                   "footer": {"text": "infra-assistant の承認ボタン"}}])


@app.post("/api/actions/{action_id}/approve")
def approve(action_id: str, request: Request) -> dict:
    ip = _client_ip(request)
    _check_approver(ip)
    a = _take(action_id)
    log.warning("approved %s from %s", a["summary"], ip)
    try:
        text = execute_action(a)
        _audit("approved", a, ip, text)
        return {"ok": True, "text": text}
    except Exception as e:  # noqa: BLE001
        log.exception("action failed")
        reason = getattr(e, "reason", None) or type(e).__name__
        _audit("approved", a, ip, f"実行できませんでした: {reason}", ok=False)
        return {"ok": False, "text": f"実行できませんでした: {reason}"}


@app.post("/api/actions/{action_id}/reject")
def reject(action_id: str, request: Request) -> dict:
    ip = _client_ip(request)
    _check_approver(ip)
    a = _take(action_id)
    log.info("rejected %s from %s", a["summary"], ip)
    _audit("rejected", a, ip, "実行しませんでした")
    return {"ok": True}
