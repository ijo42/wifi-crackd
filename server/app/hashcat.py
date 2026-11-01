"""Обёртка над hashcat -m 22000: запуск стадии, стриминг --status-json, чтение potfile.

DRY_RUN=1: фейковый запуск (для отладки без GPU): стримит статус-JSON и
записывает в potfile демо-пароли, чтобы весь пайплайн был проверяем end-to-end.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import config as cfg
from . import db
from .ingest import parse_22000

_STATUS_NAMES = {2: "Autotuning", 3: "Running", 4: "Paused", 5: "Exhausted", 6: "Cracked!"}

_HEXPLAIN = re.compile(r"\$HEX\[([0-9a-fA-F]+)\]")


def decode_plain(s: str) -> str:
    """hashcat пишет непечатаемые пароли как $HEX[...] — декодируем."""
    m = _HEXPLAIN.fullmatch(s)
    if m:
        try:
            return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
        except ValueError:
            return s
    return s


@dataclass
class StatusUpdate:
    progress: float | None = None    # 0..100
    speed_hs: str | None = None      # человекочитаемая скорость
    eta: str | None = None
    status_code: int | None = None


def _fmt_speed(speed_sec) -> str | None:
    """speed_sec: [[hashes, ms], [..], ...] по устройствам → суммарно."""
    if not speed_sec:
        return None
    total = 0.0
    for entry in speed_sec:
        if len(entry) == 2 and entry[1] > 0:
            total += entry[0] / (entry[1] / 1000.0)
    for unit, div in (("H/s", 1), ("kH/s", 1e3), ("MH/s", 1e6), ("GH/s", 1e9)):
        if total < div * 1000 or unit == "GH/s":
            return f"{total / div:.1f} {unit}"
    return None


def _fmt_eta(entry: dict) -> str | None:
    """eta: [{sec|minutes|hours|days}, ...] → человекочитаемо."""
    if not entry:
        return None
    e = entry[0] if isinstance(entry, list) else entry
    for key in ("sec", "minutes", "hours", "days"):
        if key in e:
            val = e[key]
            return {"sec": f"{val} сек", "minutes": f"{val} мин",
                    "hours": f"{val} ч", "days": f"{val} дн"}[key]
    return None


def parse_status_json(line: str) -> StatusUpdate | None:
    """Строка --status-json → StatusUpdate (по опыту wifit3: коды 2-6, progress[])."""
    line = line.strip()
    if not (line.startswith("{") and line.endswith("}")):
        return None
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    up = StatusUpdate(status_code=data.get("status"))
    prog = data.get("progress") or [0, 1]
    if len(prog) == 2 and prog[1]:
        up.progress = min(100.0, prog[0] / prog[1] * 100.0)
    up.speed_hs = _fmt_speed(data.get("speed_sec"))
    up.eta = _fmt_eta(data.get("eta"))
    return up


# ---------- potfile ----------

def read_potfile_entries(potfile: Path) -> list[dict]:
    """[{password, ssid, bssid, hashline}] из potfile (hash:plain)."""
    entries: list[dict] = []
    if not potfile.is_file():
        return entries
    for line in potfile.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if ":" not in line:
            continue
        hash_part, _, plain = line.partition(":")
        password = decode_plain(plain)
        hl = parse_22000(hash_part)
        entries.append({
            "password": password,
            "ssid": hl.ssid if hl else None,
            "bssid": hl.bssid if hl else None,
            "hashline": hash_part,
        })
    return entries


# ---------- стадии ----------

def build_cmd(hashfile: Path, stage_args: str) -> list[str]:
    cmd = [
        cfg.HASHCAT,
        "-m", "22000",
        "--potfile-path", str(cfg.POTFILE),
        "--status",
        "--status-json",
        "--status-timer", str(cfg.load_config().hashcat.status_timer),
        "-w", str(cfg.load_config().hashcat.workload),
        str(hashfile.resolve()),
    ]
    cmd.extend(stage_args.split())
    return cmd


def _strip_dead_pidfile() -> None:
    """hashcat отказывается стартовать, пока в его pidfile живой pid (опыт wifit3)."""
    for candidate in (
        Path.home() / ".hashcat" / "sessions" / "hashcat.pid",
        Path.home() / ".local" / "share" / "hashcat" / "sessions" / "hashcat.pid",
    ):
        try:
            recorded = int.from_bytes(candidate.read_bytes()[:4], "little")
        except (OSError, ValueError):
            continue
        try:
            import os
            os.kill(recorded, 0)
        except ProcessLookupError:
            try:
                candidate.unlink()
            except OSError:
                pass
        except PermissionError:
            pass
        except OSError:
            continue


class StageRun:
    """Запуск одной стадии: процесс + поток чтения stdout, статус → колбэк."""

    def __init__(self, cmd: list[str], on_status):
        self.cmd = cmd
        self.on_status = on_status
        self.proc: subprocess.Popen | None = None
        self.last_message = ""
        self.final_status_code: int | None = None
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _reader(self) -> None:
        assert self.proc and self.proc.stdout
        for raw in self.proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip("\n")
            if self._stop.is_set():
                break
            s = line.strip()
            if not s:
                continue
            if not (s.startswith("{") and s.endswith("}")):
                self.last_message = s[:200]
            up = parse_status_json(s)
            if up:
                if up.status_code in (5, 6):
                    self.final_status_code = up.status_code
                self.on_status(up)

    def run(self, timeout: int = 0) -> int:
        cfg.POTFILE.parent.mkdir(parents=True, exist_ok=True)
        _strip_dead_pidfile()
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=str(Path(cfg.HASHCAT).parent) if "/" in cfg.HASHCAT else None,
        )
        t = threading.Thread(target=self._reader, daemon=True)
        t.start()
        try:
            rc = self.proc.wait(timeout=timeout or None)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.returncode or 0
        if self._stop.is_set():
            self.proc.kill()
            return 130
        t.join(timeout=5)
        return rc

    def kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()


# ---------- DRY_RUN ----------

class DryRun(StageRun):
    """Фейк hashcat: ~3 сек стримит статус-JSON, пишет демо-пароли в potfile."""

    def __init__(self, hashfile: Path, stage_args: str, on_status):
        super().__init__([], on_status)
        self.hashfile = hashfile

    def run(self, timeout: int = 0) -> int:
        cfg.POTFILE.parent.mkdir(parents=True, exist_ok=True)
        n_hashes = 0
        try:
            n_hashes = len([l for l in self.hashfile.read_text().splitlines() if l.strip()])
        except OSError:
            pass
        stages_total = 3
        for i in range(stages_total):
            if self._stop.is_set():
                return 130
            up = StatusUpdate(status_code=3, progress=(i + 1) / stages_total * 100,
                              speed_hs="123.4 kH/s", eta="0 сек")
            self.on_status(up)
            time.sleep(1.0)
        self.final_status_code = 6
        with open(cfg.POTFILE, "a", encoding="utf-8") as f:
            for line in self.hashfile.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                hl = parse_22000(line)
                if hl:
                    f.write(f"{hl.line}:dry-run-demo\n")
        self.last_message = "DRY_RUN: фейковый прогон завершён"
        return 0


def make_stage_run(job_id: str, hashfile: Path, stage_args: str, on_status) -> StageRun:
    if cfg.DRY_RUN:
        return DryRun(hashfile, stage_args, on_status)
    return StageRun(build_cmd(hashfile, stage_args), on_status)
