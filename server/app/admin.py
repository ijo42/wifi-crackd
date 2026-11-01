"""Админ-веб: логин, дашборд, карточка задачи (Accept/Reject/Retry/Stop/Delete), токены, конфиг."""
from __future__ import annotations

import time
from pathlib import Path

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from . import config as cfg
from . import db, security
from .worker import mark_invalid, prepare_job, request_stop_job

router = APIRouter()
_APP_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))


def _ts(v) -> str:
    if not v:
        return "—"
    import datetime
    return datetime.datetime.fromtimestamp(int(v)).strftime("%d.%m %H:%M")


templates.env.filters["ts"] = _ts


def is_admin(request: Request) -> bool:
    token = request.cookies.get(security.SESSION_COOKIE, "")
    return bool(token) and security.verify_session_token(token)


def require_admin(request: Request):
    if not is_admin(request):
        raise RedirectResponse("/login", status_code=303)
    return None


def render(request: Request, name: str, ctx: dict, status_code: int = 200) -> HTMLResponse:
    ctx.setdefault("request", request)
    ctx.setdefault("admin", is_admin(request))
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


# ---------- вход ----------

@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", {})


@router.post("/login")
def login(request: Request, password: str = Form("")):
    if not security.check_admin_password(password):
        return render(request, "login.html", {"error": "неверный пароль"}, status_code=303)
    resp = RedirectResponse("/admin", status_code=303)
    resp.set_cookie(security.SESSION_COOKIE, security.make_session_token(),
                    max_age=security.SESSION_MAX_AGE, httponly=True, samesite="lax")
    return resp


@router.post("/logout")
def logout():
    resp = RedirectResponse("/", status_code=303)
    resp.delete_cookie(security.SESSION_COOKIE)
    return resp


# ---------- публичная страница загрузки ----------

@router.get("/", response_class=HTMLResponse)
def index(request: Request):
    return render(request, "upload.html", {})


# ---------- дашборд ----------

@router.get("/admin", response_class=HTMLResponse)
def dashboard(request: Request, state: str = ""):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    counts = {r["state"]: r["n"] for r in
              db.query("SELECT state, COUNT(*) AS n FROM jobs GROUP BY state")}
    if state:
        jobs = db.query("SELECT * FROM jobs WHERE state=? ORDER BY created_at DESC", (state,))
    else:
        jobs = db.query("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200")
    return render(request, "dashboard.html", {
        "jobs": [db.job_to_dict(j) for j in jobs],
        "counts": counts,
        "state": state,
    })


@router.get("/admin/jobs/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return render(request, "error.html", {"message": "задача не найдена"}, status_code=404)
    found = db.query("SELECT * FROM found WHERE job_id=? ORDER BY found_at", (job_id,))
    return render(request, "job.html", {"j": db.job_to_dict(rows[0]), "found": found})


def _admin_action(request: Request, job_id: str):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    rows = db.query("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return render(request, "error.html", {"message": "задача не найдена"}, status_code=404)
    return db.job_to_dict(rows[0])


@router.post("/admin/jobs/{job_id}/accept")
def accept(request: Request, job_id: str):
    j = _admin_action(request, job_id)
    if isinstance(j, HTMLResponse):
        return j
    if j["state"] not in ("pending", "invalid", "rejected", "stopped", "failed", "done"):
        return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)
    draft = cfg.JOBS_DIR / f"{job_id}.draft"
    if not draft.is_file():
        return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)
    lines = [l.strip() for l in draft.read_text(encoding="utf-8").splitlines() if l.strip()]
    targets = targets_from_lines(lines)
    prepare_job(job_id, lines, targets, j["ft_count"], state="queued")
    db.execute("UPDATE jobs SET accepted_at=?, n_files=COALESCE(NULLIF(n_files,0), hash_count) WHERE id=?",
               (int(time.time()), job_id))
    draft.unlink(missing_ok=True)
    return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)


def targets_from_lines(lines: list[str]) -> list[dict]:
    from .ingest import parse_22000, targets_of
    hls = [h for h in (parse_22000(l) for l in lines) if h]
    return targets_of(hls)


@router.post("/admin/jobs/{job_id}/reject")
def reject(request: Request, job_id: str, reason: str = Form("")):
    j = _admin_action(request, job_id)
    if isinstance(j, HTMLResponse):
        return j
    db.execute("UPDATE jobs SET state='rejected', error=?, finished_at=? WHERE id=?",
               (reason.strip()[:300] or "отклонено администратором", int(time.time()), job_id))
    (cfg.JOBS_DIR / f"{job_id}.draft").unlink(missing_ok=True)
    return RedirectResponse("/admin", status_code=303)


@router.post("/admin/jobs/{job_id}/retry")
def retry(request: Request, job_id: str):
    j = _admin_action(request, job_id)
    if isinstance(j, HTMLResponse):
        return j
    if not (cfg.JOBS_DIR / f"{job_id}.hc22000").is_file():
        return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)
    db.execute("UPDATE jobs SET state='queued', stage_idx=0, stage_name=NULL, progress=0, "
               "speed_hs=NULL, eta=NULL, error=NULL, finished_at=NULL, started_at=NULL WHERE id=?",
               (job_id,))
    return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)


@router.post("/admin/jobs/{job_id}/stop")
def stop(request: Request, job_id: str):
    j = _admin_action(request, job_id)
    if isinstance(j, HTMLResponse):
        return j
    request_stop_job(job_id)
    return RedirectResponse(f"/admin/jobs/{job_id}", status_code=303)


@router.post("/admin/jobs/{job_id}/delete")
def delete(request: Request, job_id: str):
    j = _admin_action(request, job_id)
    if isinstance(j, HTMLResponse):
        return j
    db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
    db.execute("DELETE FROM found WHERE job_id=?", (job_id,))
    for suffix in (".hc22000", ".draft"):
        (cfg.JOBS_DIR / f"{job_id}{suffix}").unlink(missing_ok=True)
    return RedirectResponse("/admin", status_code=303)


# ---------- токены ----------

@router.get("/admin/tokens", response_class=HTMLResponse)
def tokens_page(request: Request, new_key: str = ""):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    return render(request, "tokens.html", {
        "tokens": db.query("SELECT * FROM tokens ORDER BY created_at DESC"),
        "new_key": new_key,
    })


@router.post("/admin/tokens", response_class=HTMLResponse)
def create_token(request: Request, name: str = Form("")):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    name = name.strip()[:64]
    if not name:
        return RedirectResponse("/admin/tokens", status_code=303)
    key = security.generate_token_key()
    db.execute("INSERT INTO tokens(name, key_hash, active, created_at) VALUES(?,?,1,?)",
               (name, security.token_key_hash(key), int(time.time())))
    # ключ показываем в ответе на POST (не через redirect: не утекает в историю)
    return tokens_page(request, new_key=key)


@router.post("/admin/tokens/{token_id}/revoke")
def revoke_token(request: Request, token_id: int):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    db.execute("UPDATE tokens SET active=0 WHERE id=?", (token_id,))
    return RedirectResponse("/admin/tokens", status_code=303)


# ---------- конфиг (read-only) ----------

@router.get("/admin/config", response_class=HTMLResponse)
def config_page(request: Request):
    if not is_admin(request):
        return RedirectResponse("/login", status_code=303)
    c = cfg.load_config()
    return render(request, "config.html", {"c": c, "dry_run": cfg.DRY_RUN})
