"""Воркер: один hashcat за раз; для задачи — стадии по порядку из config.yaml.

Состояния: pending → queued → running → done | failed | stopped
(приёмка: pending|queued → invalid/rejected/queued; см. api.py/admin.py).
"""
from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path

from . import config as cfg
from . import db
from . import hashcat as hc

log = logging.getLogger("crackd.worker")

_stop_event = threading.Event()
_current_run: hc.StageRun | None = None
_current_job: str | None = None
_lock = threading.Lock()


def start_worker() -> threading.Thread:
    t = threading.Thread(target=_loop, name="crackd-worker", daemon=True)
    t.start()
    return t


# ---------- подготовка к запуску ----------

def prepare_job(job_id: str, lines: list[str], targets: list[dict], ft_count: int,
                state: str = "queued") -> None:
    """После валидной приёмки: сохранить hashfile и метаданные; задача готова к очереди."""
    cfg.JOBS_DIR.mkdir(parents=True, exist_ok=True)
    hashfile = cfg.JOBS_DIR / f"{job_id}.hc22000"
    hashfile.write_text("".join(f"{l}\n" for l in lines), encoding="utf-8", newline="\n")
    db.execute(
        "UPDATE jobs SET state=?, targets=?, hash_count=?, ft_count=?, error=NULL WHERE id=?",
        (state, json.dumps(targets), len(lines), ft_count, job_id),
    )


def mark_invalid(job_id: str, reason: str) -> None:
    db.execute("UPDATE jobs SET state='invalid', error=?, finished_at=? WHERE id=?",
               (reason, int(time.time()), job_id))


# ---------- управление ----------

def request_stop_job(job_id: str) -> bool:
    """Остановить текущую задачу (кнопка Stop в админке)."""
    with _lock:
        if _current_job == job_id and _current_run is not None:
            _current_run.stop()
            return True
    return False


def stop_all() -> None:
    _stop_event.set()
    with _lock:
        if _current_run is not None:
            _current_run.stop()


# ---------- цикл ----------

def _loop() -> None:
    while not _stop_event.is_set():
        rows = db.query("SELECT id FROM jobs WHERE state='queued' ORDER BY accepted_at LIMIT 1")
        if not rows:
            time.sleep(1.0)
            continue
        job_id = rows[0]["id"]
        try:
            _run_job(job_id)
        except Exception:
            log.exception("job %s crashed worker step", job_id)
            db.execute("UPDATE jobs SET state='failed', error='внутренняя ошибка воркера', finished_at=? WHERE id=?",
                       (int(time.time()), job_id))


def _on_status(job_id: str):
    def cb(up: hc.StatusUpdate) -> None:
        fields: dict = {}
        if up.progress is not None:
            fields["progress"] = round(up.progress, 1)
        if up.speed_hs:
            fields["speed_hs"] = up.speed_hs
        if up.eta:
            fields["eta"] = up.eta
        if fields:
            sets = ", ".join(f"{k}=?" for k in fields)
            db.execute(f"UPDATE jobs SET {sets} WHERE id=?", (*fields.values(), job_id))
    return cb


def _save_found(job_id: str, known_hashlines: set[str], stage_name: str) -> int:
    """Новые записи potfile → таблица found. Возвращает число новых."""
    saved = 0
    for entry in hc.read_potfile_entries(cfg.POTFILE):
        if entry["hashline"] in known_hashlines:
            continue
        known_hashlines.add(entry["hashline"])
        db.execute(
            "INSERT INTO found(job_id, ssid, bssid, password, stage, found_at) VALUES(?,?,?,?,?,?)",
            (job_id, entry["ssid"], entry["bssid"], entry["password"], stage_name, int(time.time())),
        )
        saved += 1
    return saved


def _cracked_all(hashfile: Path) -> bool:
    """Все строки файла уже в potfile → брутить больше нечего (potfile общий)."""
    entries = {e["hashline"] for e in hc.read_potfile_entries(cfg.POTFILE)}
    if not entries:
        return False
    try:
        lines = [l.strip() for l in hashfile.read_text(encoding="utf-8").splitlines() if l.strip()]
    except OSError:
        return False
    return bool(lines) and all(l in entries for l in lines)


def _run_job(job_id: str) -> None:
    global _current_run, _current_job
    db.execute("UPDATE jobs SET state='running', started_at=?, stage_idx=0, error=NULL WHERE id=?",
               (int(time.time()), job_id))

    hashfile = cfg.JOBS_DIR / f"{job_id}.hc22000"
    if not hashfile.is_file():
        db.execute("UPDATE jobs SET state='failed', error='hashfile отсутствует', finished_at=? WHERE id=?",
                   (int(time.time()), job_id))
        return

    known: set[str] = {e["hashline"] for e in hc.read_potfile_entries(cfg.POTFILE)}
    stages = cfg.load_config().stages
    if not stages:
        db.execute("UPDATE jobs SET state='failed', error='в config.yaml нет стадий брута', finished_at=? WHERE id=?",
                   (int(time.time()), job_id))
        return
    failed = False

    for idx, stage in enumerate(stages):
        if _cracked_all(hashfile):
            break
        db.execute("UPDATE jobs SET stage_idx=?, stage_name=?, progress=0 WHERE id=?",
                   (idx, stage.name, job_id))
        log.info("job %s: stage %s (%s)", job_id, stage.name, stage.args)
        run = hc.make_stage_run(job_id, hashfile, stage.args, _on_status(job_id))
        with _lock:
            _current_run, _current_job = run, job_id
        rc = run.run()
        with _lock:
            _current_run = None
        _save_found(job_id, known, stage.name)
        if rc == 130:  # Stop по кнопке в админке
            db.execute("UPDATE jobs SET state='stopped', finished_at=? WHERE id=?",
                       (int(time.time()), job_id))
            return
        if rc != 0:
            db.execute("UPDATE jobs SET state='failed', error=?, finished_at=? WHERE id=?",
                       (run.last_message or f"hashcat exit {rc}", int(time.time()), job_id))
            failed = True
            break
        if run.final_status_code == 6:  # cracked — все строки взяты, дальше не идём
            break

    if not failed:
        db.execute("UPDATE jobs SET state='done', progress=100, stage_name=NULL, speed_hs=NULL, eta=NULL, finished_at=? WHERE id=?",
                   (int(time.time()), job_id))
