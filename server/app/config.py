"""Конфигурация wifi-crackd: YAML-файл стадий/лимитов + переменные окружения."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Каталоги (в контейнере /data — volume, /wordlists — read-only volume)
DATA_DIR = Path(os.environ.get("CRACKD_DATA", "/data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOBS_DIR = DATA_DIR / "jobs"
POTFILE = DATA_DIR / "hashcat.potfile"
DB_PATH = DATA_DIR / "crackd.db"
CONFIG_PATH = Path(os.environ.get("CRACKD_CONFIG", "/app/config.yaml"))
WORDLISTS_DIR = Path(os.environ.get("CRACKD_WORDLISTS", "/wordlists"))

DRY_RUN = os.environ.get("DRY_RUN", "0") == "1"
DRY_RUN_SECS = int(os.environ.get("DRY_RUN_SECS", "3"))  # длительность фейкового прогона
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")

HCXPCAPNGTOOL = os.environ.get("HCXPCAPNGTOOL", "hcxpcapngtool")
HASHCAT = os.environ.get("HASHCAT_BIN", "hashcat")

# ---------- YAML ----------

@dataclass
class Stage:
    name: str
    args: str


@dataclass
class Limits:
    max_upload_mb: int = 64
    max_files: int = 512
    anon_rate_per_hour: int = 10
    anon_pending_cap: int = 50


@dataclass
class HashcatOpts:
    workload: int = 3
    status_timer: int = 5


@dataclass
class AppConfig:
    stages: list[Stage] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)
    retention_days: int = 30
    hashcat: HashcatOpts = field(default_factory=HashcatOpts)


def load_config(path: Path = CONFIG_PATH) -> AppConfig:
    """Читает YAML; отсутствующий файл = пустой набор стадий (сервис работает)."""
    cfg = AppConfig()
    if not path.is_file():
        return cfg
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    for st in raw.get("stages") or []:
        name = str(st.get("name", "")).strip()
        args = str(st.get("args", "")).strip()
        if name and args:
            cfg.stages.append(Stage(name=name, args=args))
    lim = raw.get("limits") or {}
    cfg.limits = Limits(
        max_upload_mb=int(lim.get("max_upload_mb", cfg.limits.max_upload_mb)),
        max_files=int(lim.get("max_files", cfg.limits.max_files)),
        anon_rate_per_hour=int(lim.get("anon_rate_per_hour", cfg.limits.anon_rate_per_hour)),
        anon_pending_cap=int(lim.get("anon_pending_cap", cfg.limits.anon_pending_cap)),
    )
    cfg.retention_days = int(raw.get("retention_days", cfg.retention_days))
    hc = raw.get("hashcat") or {}
    cfg.hashcat = HashcatOpts(
        workload=int(hc.get("workload", cfg.hashcat.workload)),
        status_timer=int(hc.get("status_timer", cfg.hashcat.status_timer)),
    )
    return cfg
