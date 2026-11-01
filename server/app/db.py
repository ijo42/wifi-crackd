"""SQLite (WAL): задачи, найденные пароли, токены, rate-limit."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import config as cfg

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id            TEXT PRIMARY KEY,
    secret_hash   TEXT NOT NULL,
    state         TEXT NOT NULL DEFAULT 'pending',
    source        TEXT NOT NULL DEFAULT 'anon',
    token_name    TEXT,
    note          TEXT,
    uploader_ip   TEXT,
    n_files       INTEGER DEFAULT 0,
    targets       TEXT DEFAULT '[]',      -- JSON: [{ssid,bssid,kind,count}]
    hash_count    INTEGER DEFAULT 0,      -- валидных строк 22000
    ft_count      INTEGER DEFAULT 0,      -- отфильтровано FT (WPA*03/04)
    stage_idx     INTEGER DEFAULT 0,
    stage_name    TEXT,
    progress      REAL DEFAULT 0,         -- 0..100 текущего этапа
    speed_hs      TEXT,
    eta           TEXT,
    error         TEXT,
    created_at    INTEGER NOT NULL,
    accepted_at   INTEGER,
    started_at    INTEGER,
    finished_at   INTEGER
);
CREATE TABLE IF NOT EXISTS found (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id    TEXT NOT NULL,
    ssid      TEXT,
    bssid     TEXT,
    password  TEXT NOT NULL,
    stage     TEXT,
    found_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);
CREATE TABLE IF NOT EXISTS rate (
    ip        TEXT NOT NULL,
    ts        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_ip ON rate(ip, ts);
CREATE INDEX IF NOT EXISTS idx_found_job ON found(job_id);
"""


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    global _conn
    with _lock:
        if _conn is not None:
            return _conn
        path = db_path or cfg.DB_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(SCHEMA)
        conn.commit()
        _conn = conn
        return conn


def reset_for_tests() -> None:
    """Закрыть соединение (тесты открывают своё на tmp-путь)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None


def query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    return connect().execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> None:
    conn = connect()
    with _lock:
        conn.execute(sql, params)
        conn.commit()


def job_to_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["targets"] = json.loads(d.get("targets") or "[]")
    return d


# ---------- rate limit ----------

def anon_rate_ok(ip: str, limit_per_hour: int) -> bool:
    conn = connect()
    now = int(time.time())
    with _lock:
        conn.execute("DELETE FROM rate WHERE ts < ?", (now - 3600,))
        n = conn.execute("SELECT COUNT(*) FROM rate WHERE ip=? AND ts>=?", (ip, now - 3600)).fetchone()[0]
        if n >= limit_per_hour:
            conn.commit()
            return False
        conn.execute("INSERT INTO rate(ip, ts) VALUES(?,?)", (ip, now))
        conn.commit()
        return True


def pending_count() -> int:
    row = query("SELECT COUNT(*) AS n FROM jobs WHERE state='pending'")[0]
    return int(row["n"])
