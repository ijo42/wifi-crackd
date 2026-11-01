"""Retention: удаление старых завершённых задач и их файлов."""
from __future__ import annotations

import logging
import threading
import time

from . import config as cfg
from . import db

log = logging.getLogger("crackd.cleanup")

TERMINAL = ("done", "failed", "stopped", "invalid", "rejected")


def cleanup_once(retention_days: int) -> int:
    cutoff = int(time.time()) - retention_days * 86400
    rows = db.query(
        f"SELECT id FROM jobs WHERE state IN ({','.join('?' * len(TERMINAL))}) "
        "AND finished_at IS NOT NULL AND finished_at < ?", (*TERMINAL, cutoff))
    for r in rows:
        job_id = r["id"]
        db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        db.execute("DELETE FROM found WHERE job_id=?", (job_id,))
        for suffix in (".hc22000", ".draft"):
            (cfg.JOBS_DIR / f"{job_id}{suffix}").unlink(missing_ok=True)
        d = cfg.UPLOAD_DIR / job_id
        if d.is_dir():
            shutil_rmtree(d)
    return len(rows)


def shutil_rmtree(p):
    import shutil
    shutil.rmtree(p, ignore_errors=True)


def start_cleanup() -> threading.Thread:
    def loop() -> None:
        while True:
            try:
                n = cleanup_once(cfg.load_config().retention_days)
                if n:
                    log.info("retention: удалено задач: %d", n)
            except Exception:
                log.exception("cleanup failed")
            time.sleep(3600)

    t = threading.Thread(target=loop, name="crackd-cleanup", daemon=True)
    t.start()
    return t
