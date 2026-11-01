"""wifi-crackd: FastAPI-приложение (API + веб-админка) с воркером hashcat."""
from __future__ import annotations

import logging

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import config as cfg
from . import db
from .admin import router as admin_router
from .api import router as api_router
from .cleanup import start_cleanup
from .worker import start_worker

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="wifi-crackd", docs_url=None, redoc_url=None)


@app.on_event("startup")
def startup() -> None:
    db.connect()
    cfg.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    cfg.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    start_worker()
    start_cleanup()


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True, "dry_run": cfg.DRY_RUN}


app.include_router(api_router)
app.include_router(admin_router)
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
