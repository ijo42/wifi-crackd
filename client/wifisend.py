#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["httpx>=0.27"]
# ///
"""wifisend — отправка хендшейков/PMKID из папки захватов на сервер wifi-crackd.

Запуск (кроссплатформенно, uv сам ставит зависимости):
    uv run wifisend.py <папка с захватами> --url http://сервер:8080 [опции]

Примеры:
    uv run wifisend.py ./captures --url http://10.0.0.5:8080
    uv run wifisend.py ./captures --url http://10.0.0.5:8080 --token wfk_... --wait

Что берём: *.hc22000 *.22000 *.pmkid *.16800 *.pcap *.cap *.pcapng *.hccapx
Что пропускаем (служебное wifit3/wifite3): *.meta, jobs.json, jobs/, *_wpa_psk.txt,
*_wps_*.txt, *_wep_key.txt, *.log, *.potfile, wifit3_captures_*.zip, pwnd/, *.cracked.

Только для сетей, владеть/аудит которых ты имеешь право.
"""
from __future__ import annotations

import argparse
import io
import os
import sys
import time
import zipfile
from pathlib import Path

import httpx

TAKE = {".hc22000", ".22000", ".pmkid", ".16800", ".pcap", ".cap", ".pcapng", ".hccapx"}
SKIP_DIRS = {"jobs", "pwnd"}
SKIP_NAMES = {"jobs.json"}
SKIP_SUFFIXES = (
    ".meta", ".log", ".potfile", ".cracked",
    "_wpa_psk.txt", "_wps_pin.txt", "_wps_pbc.txt", "_wep_key.txt",
)
SKIP_GLOB_PREFIX = "wifit3_captures_"  # *.zip экспортов wifit3

STATE_LABELS = {
    "pending": "ждёт подтверждения админом",
    "queued": "в очереди",
    "running": "брутится",
    "done": "готово",
    "failed": "ошибка",
    "stopped": "остановлено",
    "invalid": "не принято (нет валидных хэшей)",
    "rejected": "отклонено админом",
}
TERMINAL = {"done", "failed", "stopped", "invalid", "rejected"}


def collect(folder: Path) -> list[Path]:
    files: list[Path] = []
    for p in sorted(folder.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(folder).parts[:-1]):
            continue
        if p.name in SKIP_NAMES or p.name.startswith(SKIP_GLOB_PREFIX):
            continue
        if p.suffix.lower() not in TAKE:
            continue
        if p.name.lower().endswith(SKIP_SUFFIXES):
            continue
        files.append(p)
    return files


def make_zip(files: list[Path], folder: Path, max_mb: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        total = 0
        for f in files:
            total += f.stat().st_size
            if total > max_mb * 1024 * 1024:
                sys.exit(f"ошибка: суммарный размер захватов > {max_mb} МБ (лимит сервера)")
            zf.writestr(f.relative_to(folder).as_posix(), f.read_bytes())
    return buf.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="wifisend",
        description="отправка захватов (wifit3/wifite3) на сервер wifi-crackd")
    ap.add_argument("folder", type=Path, nargs="?", help="папка с захватами (captures wifit3 / вывод wifite3)")
    ap.add_argument("--url", default=os.environ.get("CRACKD_URL", "http://127.0.0.1:8080"))
    ap.add_argument("--token", default=os.environ.get("CRACKD_TOKEN", ""),
                    help="wfk_… (без него — анонимно, задача ждёт акцепта админа)")
    ap.add_argument("--note", default="", help="заметка для админа")
    ap.add_argument("--wait", action="store_true", help="ждать завершения, печатая статус")
    ap.add_argument("--poll", type=float, default=5.0, help="интервал опроса статуса, сек")
    ap.add_argument("--version", action="version", version="wifisend 0.1.0")
    args = ap.parse_args()

    folder = args.folder
    if folder is None or not folder.is_dir():
        sys.exit(f"ошибка: {folder} не папка")

    files = collect(folder)
    if not files:
        sys.exit(f"ошибка: в {folder} нет подходящих файлов ({', '.join(sorted(TAKE))})")
    total_mb = sum(f.stat().st_size for f in files) / 1024 / 1024
    print(f"найдено файлов: {len(files)} ({total_mb:.1f} МБ):")
    for f in files[:10]:
        print(f"  {f.relative_to(folder)}")
    if len(files) > 10:
        print(f"  … и ещё {len(files) - 10}")

    url = args.url.rstrip("/")
    zip_bytes = make_zip(files, folder, max_mb=64)
    headers = {"Authorization": f"Bearer {args.token}"} if args.token else {}

    print(f"отправка на {url} …")
    try:
        resp = httpx.post(
            f"{url}/api/upload",
            headers=headers,
            data={"note": args.note},
            files={"captures": ("captures.zip", zip_bytes, "application/zip")},
            timeout=120,
        )
    except httpx.HTTPError as exc:
        sys.exit(f"ошибка сети: {exc}")
    if resp.status_code != 200:
        try:
            detail = resp.json().get("detail", resp.status_code)
        except Exception:
            detail = resp.status_code
        sys.exit(f"сервер отказал: {detail}")

    data = resp.json()
    print()
    print(f"job_id: {data['job_id']}")
    print(f"secret: {data['secret']}   (сохрани — без него статус не узнать)")
    print(f"хэшей принято: {data['hash_count']}" +
          (f" (FT отфильтровано: {data['ft_count']})" if data.get("ft_count") else ""))
    for t in data.get("targets", [])[:5]:
        print(f"  {t['ssid'] or '(hidden)'} {t['bssid']} {t['kind']} ×{t['count']}")
    print(f"статус: {data['state']} — {data['note']}")

    if args.wait:
        print()
        secret = data["secret"]
        prev = None
        while True:
            time.sleep(args.poll)
            try:
                r = httpx.get(f"{url}/api/jobs/{data['job_id']}", params={"secret": secret}, timeout=30)
                j = r.json()
            except httpx.HTTPError:
                continue
            cur = (j["state"], j.get("stage_name"), j.get("progress"))
            if cur != prev:
                label = STATE_LABELS.get(j["state"], j["state"])
                line = f"[{time.strftime('%H:%M:%S')}] {label}"
                if j["state"] == "running":
                    line += f": {j.get('stage_name') or ''} {j.get('progress') or 0:.0f}%" \
                            f" {j.get('speed_hs') or ''} ETA {j.get('eta') or '—'}"
                if j["state"] in ("failed", "invalid", "rejected") and j.get("error"):
                    line += f": {j['error']}"
                print(line)
                prev = cur
            if j["state"] in TERMINAL:
                print(f"итог: {STATE_LABELS.get(j['state'], j['state'])}")
                print("результаты — у администратора в веб-админке")
                break


if __name__ == "__main__":
    main()
