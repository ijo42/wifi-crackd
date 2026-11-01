"""Публичный API: анонимная/токенная загрузка + статус задачи (без паролей)."""
from __future__ import annotations

import json
import time
import uuid

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile

from . import config as cfg
from . import db, security
from .ingest import ingest_zip, targets_of
from .worker import mark_invalid, prepare_job

router = APIRouter(prefix="/api")


def _err(status: int, msg: str) -> HTTPException:
    return HTTPException(status_code=status, detail=msg)


@router.post("/upload")
async def upload(request: Request, captures: UploadFile = File(...),
                 note: str = Form("")) -> dict:
    lim = cfg.load_config().limits
    ip = security.client_ip(request)

    # токен?
    auth = request.headers.get("authorization", "")
    token_key = auth.removeprefix("Bearer ").strip() if auth.lower().startswith("bearer ") else ""
    source, token_name = "anon", None
    if token_key:
        rows = db.query("SELECT name, active FROM tokens WHERE key_hash=?",
                        (security.token_key_hash(token_key),))
        if not rows or not rows[0]["active"]:
            raise _err(401, "неверный или отозванный токен")
        source, token_name = "token", rows[0]["name"]
        db.execute("UPDATE tokens SET last_used_at=? WHERE name=?", (int(time.time()), token_name))

    # лимиты
    if source == "anon":
        if not db.anon_rate_ok(ip, lim.anon_rate_per_hour):
            raise _err(429, f"превышен лимит {lim.anon_rate_per_hour} загрузок/час с одного IP")
        if db.pending_count() >= lim.anon_pending_cap:
            raise _err(503, "очередь анонимных задач переполнена, попробуй позже")

    max_bytes = lim.max_upload_mb * 1024 * 1024 + 1
    data = await captures.read(max_bytes)
    if len(data) > lim.max_upload_mb * 1024 * 1024:
        raise _err(413, f"архив больше {lim.max_upload_mb} МБ")
    if not data:
        raise _err(400, "пустой файл")

    job_id = uuid.uuid4().hex[:12]
    secret = security.new_job_secret()
    now = int(time.time())
    db.execute(
        "INSERT INTO jobs(id, secret_hash, state, source, token_name, note, uploader_ip, created_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (job_id, security.job_secret_hash(secret), "pending", source, token_name,
         note.strip()[:300] or None, ip, now),
    )

    # приёмка (синхронно: ≤64 МБ, hcxpcapngtool быстрый)
    try:
        res = ingest_zip(data, lim.max_files, lim.max_upload_mb)
    except ValueError as exc:
        mark_invalid(job_id, str(exc))
        raise _err(400, str(exc)) from None

    targets = targets_of(res.lines)
    if not targets:
        mark_invalid(job_id, "в архиве нет валидных строк WPA*01/02 (22000)")
        raise _err(400, "в архиве нет валидных строк WPA*01/02 (22000)")

    if source == "token":
        prepare_job(job_id, [hl.line for hl in res.lines], targets, res.ft_count, state="queued")
    else:
        # аноним: сохраняем черновик, ждём акцепта админа
        cfg.JOBS_DIR.mkdir(parents=True, exist_ok=True)
        (cfg.JOBS_DIR / f"{job_id}.draft").write_text(
            "".join(f"{hl.line}\n" for hl in res.lines), encoding="utf-8", newline="\n")
        db.execute("UPDATE jobs SET n_files=?, targets=?, hash_count=?, ft_count=? WHERE id=?",
                   (res.n_files, json.dumps(targets), len(res.lines), res.ft_count, job_id))

    return {
        "job_id": job_id,
        "secret": secret,
        "state": db.query("SELECT state FROM jobs WHERE id=?", (job_id,))[0]["state"],
        "hash_count": len(res.lines),
        "ft_count": res.ft_count,
        "targets": targets,
        "note": ("задача ждёт подтверждения администратора" if source == "anon"
                 else "задача поставлена в очередь"),
    }


@router.get("/jobs/{job_id}")
def job_status(job_id: str, secret: str = "") -> dict:
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows or not secret or security.job_secret_hash(secret) != rows[0]["secret_hash"]:
        raise _err(404, "задача не найдена (job_id/secret неверны)")
    j = db.job_to_dict(rows[0])
    # только статус, без паролей и прочих деталей
    return {
        "job_id": j["id"],
        "state": j["state"],
        "stage_name": j["stage_name"],
        "progress": j["progress"],
        "speed_hs": j["speed_hs"],
        "eta": j["eta"],
        "error": j["error"],
        "hash_count": j["hash_count"],
        "created_at": j["created_at"],
        "finished_at": j["finished_at"],
    }
