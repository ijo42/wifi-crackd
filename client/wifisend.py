#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["httpx>=0.27"]
# ///
"""wifisend — отправка WiFi-хендшейков/PMKID на Hashtopolis пачками.

Собирает захваты из папки (wifit3/wifite3), конвертирует в hc22000,
разбивает на батчи и для каждого батча создаёт hashlist + цепочку задач
из готовых pretask'ов сервера (словари → правила → маски).

Запуск (кроссплатформенно, uv сам ставит зависимости):
    uv run wifisend.py <папка с захватами> --url https://hashtopolis.example.com

Аутентификация (одно из):
    --token <JWT/API-token>           или env HTP_TOKEN
    --user/--password (basic)         или env HTP_USER / HTP_PASSWORD

Примеры:
    uv run wifisend.py ./captures --url https://htp.example.com --user admin --password …
    uv run wifisend.py ./captures --url http://10.0.0.5:8081 --batch 250 --wait
    uv run wifisend.py ./captures --dry-run          # показать, что будет отправлено

Конвертация: текстовые *.hc22000/*.22000/*.pmkid/*.16800 берутся напрямую;
*.pcap/*.cap/*.pcapng/*.hccapx конвертируются внешним hcxpcapngtool
(флаг --hcxtool, по умолчанию «hcxpcapngtool» в PATH).

Цепочка атак по умолчанию — pretask'и сервера, отбираемые по подстрокам имени
(см. --pretask/--list-pretasks). Только для сетей, аудит которых тебе разрешён.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx


def config_path() -> Path:
    return Path(os.environ.get(
        "WIFISEND_CONFIG",
        str(Path.home() / ".config" / "wifisend" / "config.json"),
    )).expanduser()


def load_config() -> dict:
    try:
        return json.loads(config_path().read_text())
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    p = config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2) + "\n")

TAKE_TEXT = {".hc22000", ".22000", ".pmkid", ".16800"}
TAKE_PCAP = {".pcap", ".cap", ".pcapng", ".hccapx"}
SKIP_DIRS = {"jobs", "pwnd"}
SKIP_NAMES = {"jobs.json"}
SKIP_SUFFIXES = (
    ".meta", ".log", ".potfile", ".cracked",
    "_wpa_psk.txt", "_wps_pin.txt", "_wps_pbc.txt", "_wep_key.txt",
)
SKIP_GLOB_PREFIX = "wifit3_captures_"

# дефолтная эскалационная цепочка: подстроки имён pretask'ов сервера (по порядку)
DEFAULT_CHAIN = (
    "dict router-defaults",
    "rule OneRule x router-defaults",
    "dict ru-phone-round",
    "mask 8 digits",
    "mask RU mobile 8-9xx",
)


def collect(folder: Path) -> list[Path]:
    files: list[Path] = []
    for p in sorted(folder.rglob("*")):
        if not p.is_file():
            continue
        if any(part in SKIP_DIRS for part in p.relative_to(folder).parts[:-1]):
            continue
        if p.name in SKIP_NAMES or p.name.startswith(SKIP_GLOB_PREFIX):
            continue
        if p.suffix.lower() not in TAKE_TEXT | TAKE_PCAP:
            continue
        if p.name.lower().endswith(SKIP_SUFFIXES):
            continue
        files.append(p)
    return files


def looks_like_hc22000(line: str) -> bool:
    parts = line.split("*")
    return len(parts) >= 5 and parts[0].upper() in ("WPA", "PMKID", "HCPMX")


def extract_text(p: Path) -> list[str]:
    out = []
    for raw in p.read_text(errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def extract_pcap(p: Path, hcxtool: str) -> list[str]:
    with tempfile.TemporaryDirectory(prefix="wifisend-") as td:
        out = Path(td) / "out.22000"
        proc = subprocess.run(
            [hcxtool, "-o", str(out), str(p)],
            capture_output=True, text=True, timeout=120,
        )
        if not out.exists():
            sys.stderr.write(
                f"  ! {p.name}: hcxpcapngtool не дал hc22000 "
                f"(rc={proc.returncode}); возможно, в захвате нет WPA-пакетов\n")
            return []
        return [l.strip() for l in out.read_text().splitlines() if l.strip()]


class Hashtopolis:
    def __init__(self, url: str, token: str | None,
                 user: str | None, password: str | None):
        self.url = url.rstrip("/")
        self._static = token or None
        self._user, self._password = user, password
        self._jwt: str | None = None
        self.http = httpx.Client(timeout=60)

    def on_authed(self) -> None:
        """Persist url (+ long-lived static token) after a successful authed call."""
        cfg = {"url": self.url, "user": self._user or ""}
        if self._static:
            cfg["token"] = self._static
        try:
            save_config(cfg)
        except Exception as exc:
            sys.stderr.write(f"  ! не удалось сохранить конфиг: {exc}\n")

    def _auth_header(self) -> dict[str, str]:
        if self._static:
            return {"Authorization": f"Bearer {self._static}"}
        if not self._jwt:
            self._jwt = self._login()
        return {"Authorization": f"Bearer {self._jwt}"}

    def _login(self) -> str:
        r = self.http.post(f"{self.url}/api/v2/auth/token",
                           json=["role.all"],
                           auth=(self._user, self._password or ""))
        if r.status_code != 201:
            sys.exit(f"ошибка: логин {self._user!r} отклонён (HTTP {r.status_code}): {r.text[:200]}")
        return r.json()["token"]

    def get(self, path: str, retry_auth: bool = True) -> dict:
        r = self.http.get(f"{self.url}{path}", headers=self._auth_header())
        if r.status_code == 401 and retry_auth and not self._static:
            self._jwt = self._login()
            return self.get(path, retry_auth=False)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, payload: dict) -> dict:
        r = self.http.post(f"{self.url}{path}", headers=self._auth_header(), json=payload)
        if r.status_code >= 400:
            raise RuntimeError(f"POST {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def post_raw(self, path: str, payload: dict, retry_auth: bool = True) -> dict:
        r = self.http.post(f"{self.url}{path}", headers=self._auth_header(), json=payload)
        if r.status_code == 401 and retry_auth and not self._static:
            self._jwt = self._login()
            return self.post_raw(path, payload, retry_auth=False)
        if r.status_code >= 400:
            raise RuntimeError(f"POST {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    # --- domain helpers -------------------------------------------------
    def newest_binary(self) -> tuple[int, str]:
        data = self.get("/api/v2/ui/crackers")["data"]
        if not data:
            sys.exit("ошибка: на сервере нет cracker binary — залей hashcat (make-hashcat-binary.sh)")
        best = max(data, key=lambda d: tuple(map(int, d["attributes"]["version"].split("."))))
        return int(best["id"]), best["attributes"]["version"]

    def pretasks(self) -> list[dict]:
        return self.get("/api/v2/ui/pretasks?page%5Bsize%5D=10000")["data"]

    def pretask_file_ids(self, pretask_id: int) -> list[int]:
        rel = self.get(f"/api/v2/ui/pretasks/{pretask_id}/pretaskFiles")
        return [int(d["id"]) for d in rel.get("data", [])]

    def create_hashlist(self, name: str, lines: list[str], access_group: int, note: str) -> int:
        src = "\n".join(lines)
        b64 = base64.b64encode(src.encode()).decode()
        resp = self.post_raw("/api/v2/ui/hashlists", {"data": {
            "type": "hashlist",
            "attributes": {
                "sourceType": "paste", "sourceData": b64, "name": name,
                "format": 0, "hashTypeId": 22000, "hashCount": len(lines),
                "isSecret": False, "isHexSalt": False, "isSalted": False,
                "accessGroupId": access_group, "notes": note,
                "useBrain": False, "brainFeatures": 0, "isArchived": False,
            },
        }})
        hl_id = resp.get("data", {}).get("id")
        if not hl_id:
            raise RuntimeError(f"hashlist не создан: {str(resp)[:300]}")
        return int(hl_id)

    def create_task_from_pretask(self, pretask: dict, hashlist_id: int,
                                 binary_id: int, name: str) -> int:
        a = pretask["attributes"]
        file_ids = self.pretask_file_ids(int(pretask["id"]))
        resp = self.post_raw("/api/v2/ui/tasks", {"data": {
            "type": "task",
            "attributes": {
                "hashlistId": hashlist_id,
                "files": file_ids,
                "taskName": name,
                "attackCmd": a["attackCmd"],
                "chunkTime": a.get("chunkTime", 600),
                "statusTimer": a.get("statusTimer", 5),
                # fixed 1: server computes keyspace per task via slow background
                # jobs — higher priority gets agents picked up sooner
                "priority": max(1, a.get("priority") or 1),
                "maxAgents": a.get("maxAgents", 0),
                "isSmall": bool(a.get("isSmall", False)),
                "isCpuTask": bool(a.get("isCpuTask", False)),
                "useNewBench": bool(a.get("useNewBench", True)),
                "skipKeyspace": 0,
                "crackerBinaryId": binary_id,
                "crackerBinaryTypeId": a.get("crackerBinaryTypeId"),
                "isArchived": False,
                "notes": f"pretask#{pretask['id']}",
                "staticChunks": 0,
                "chunkSize": a.get("chunkSize", 600),
                "forcePipe": bool(a.get("forcePipe", False)),
                "preprocessorId": a.get("preprocessorId", 0),
                "preprocessorCommand": a.get("preprocessorCommand", ""),
                "color": "",
            },
        }})
        tid = resp.get("data", {}).get("id")
        if not tid:
            raise RuntimeError(f"task не создан: {str(resp)[:300]}")
        return int(tid)

    def hashlist_state(self, hl_id: int) -> tuple[int, int]:
        d = self.get(f"/api/v2/ui/hashlists/{hl_id}")["data"]["attributes"]
        return int(d.get("cracked") or 0), int(d.get("hashCount") or 0)


def main() -> None:
    ap = argparse.ArgumentParser(
        prog="wifisend",
        description="отправка WiFi-хендшейков на Hashtopolis пачками (hashlist + цепочка pretask'ов)")
    ap.add_argument("folder", type=Path, nargs="?", help="папка с захватами (wifit3/wifite3 или *.hc22000)")
    ap.add_argument("--url", default=os.environ.get("HTP_URL", ""),
                    help="базовый URL Hashtopolis (env HTP_URL)")
    ap.add_argument("--token", default=os.environ.get("HTP_TOKEN", ""),
                    help="готовый JWT/API-токен (env HTP_TOKEN); иначе --user/--password")
    ap.add_argument("--user", default=os.environ.get("HTP_USER", ""))
    ap.add_argument("--password", default=os.environ.get("HTP_PASSWORD", ""))
    ap.add_argument("--access-group", type=int, default=1)
    ap.add_argument("--batch", type=int, default=250,
                    help="строк hc22000 на один hashlist (по умолчанию 250)")
    ap.add_argument("--tag", default="hs", help="префикс имён hashlist'ов")
    ap.add_argument("--note", default="", help="заметка в notes hashlist'ов")
    ap.add_argument("--pretask", type=int, action="append", dest="pretasks",
                    help="id pretask'а для цепочки (повторяемый); по умолчанию — авто-подбор по именам")
    ap.add_argument("--all-wpa-pretasks", action="store_true",
                    help="взять ВСЕ pretask'и с префиксом 'WPA2 |'")
    ap.add_argument("--list-pretasks", action="store_true",
                    help="показать pretask'и сервера и выйти")
    ap.add_argument("--hcxtool", default="hcxpcapngtool",
                    help="путь к hcxpcapngtool для конвертации pcap (по умолчанию в PATH)")
    ap.add_argument("--dry-run", action="store_true", help="показать план и выйти")
    ap.add_argument("--wait", action="store_true", help="ждать крэка, печатая прогресс")
    ap.add_argument("--poll", type=float, default=15.0, help="интервал опроса, сек")
    ap.add_argument("--timeout", type=float, default=0,
                    help="лимит ожидания в секундах (0 = без лимита)")
    ap.add_argument("--version", action="version", version="wifisend 0.2.0")
    ap.add_argument("--no-save", action="store_true",
                    help="не сохранять url/token в ~/.config/wifisend/config.json")
    args = ap.parse_args()

    # приоритет: CLI/env → сохранённый конфиг
    cfg = load_config()
    url = args.url or cfg.get("url", "")
    if not url:
        sys.exit("ошибка: укажи --url https://hashtopolis… (или env HTP_URL; "
                 f"или сохрани однажды — конфиг: {config_path()})")
    # статический токен — долговечный, его можно хранить; JWT от логина — нет
    token = args.token or ("" if args.password else cfg.get("token", ""))
    user = args.user or cfg.get("user", "admin")
    password = args.password

    htp = Hashtopolis(url, token, user, password)

    def persist() -> None:
        if not args.no_save:
            htp.on_authed()

    if args.list_pretasks:
        pts = htp.pretasks()
        persist()
        for pt in pts:
            print(f"  id={pt['id']:>3}  {pt['attributes']['taskName']}")
        return

    folder = args.folder
    if folder is None or not folder.is_dir():
        sys.exit(f"ошибка: {folder} не папка")

    # --- 1. сбор и конвертация ------------------------------------------
    files = collect(folder)
    if not files:
        sys.exit(f"ошибка: в {folder} нет подходящих файлов")
    print(f"найдено файлов: {len(files)}")

    lines: dict[str, str] = {}      # line -> source file (для отчёта)
    skipped_pcap = 0
    for f in files:
        try:
            if f.suffix.lower() in TAKE_TEXT:
                got = extract_text(f)
            else:
                got = extract_pcap(f, args.hcxtool)
        except FileNotFoundError:
            print(f"  ! {f.name}: hcxpcapngtool не найден ({args.hcxtool}); пропуск")
            skipped_pcap += 1
            continue
        except subprocess.TimeoutExpired:
            print(f"  ! {f.name}: конвертация дольше 120 с — пропуск")
            skipped_pcap += 1
            continue
        for line in got:
            lines.setdefault(line, f.name)
        print(f"  {f.relative_to(folder)}: +{len(got)} строк")

    if not lines:
        sys.exit("ошибка: ни одного валидного hc22000-хеша не извлечено")
    bad = [l for l in lines if not looks_like_hc22000(l)]
    if bad:
        print(f"  (без валидного формата WPA*/PMKID — пропущено {len(bad)})")
        for l in bad:
            lines.pop(l)
    if skipped_pcap:
        print(f"  пропущено захватов без hcxtool: {skipped_pcap}")

    ordered = sorted(lines)
    batches = [ordered[i:i + args.batch] for i in range(0, len(ordered), args.batch)]
    print(f"итого уникальных хешей: {len(ordered)} → {len(batches)} батч(ей) по ≤{args.batch}")

    # --- 2. выбор pretask-цепочки ---------------------------------------
    all_pts = htp.pretasks()
    persist()   # первый успешный авторизованный вызов — сохраняем url/token
    if args.pretasks:
        chain = [pt for pt in all_pts if int(pt["id"]) in set(args.pretasks)]
        missing = set(args.pretasks) - {int(pt["id"]) for pt in chain}
        if missing:
            sys.exit(f"ошибка: pretask(и) не найдены: {sorted(missing)}")
    elif args.all_wpa_pretasks:
        chain = [pt for pt in all_pts if pt["attributes"]["taskName"].startswith("WPA2 |")]
    else:
        chain = [pt for pt in all_pts
                 if any(s in pt["attributes"]["taskName"] for s in DEFAULT_CHAIN)]
    if not chain:
        sys.exit("ошибка: на сервере нет подходящих pretask'ов — создай их (04-wifi.sh / 05-rules.sh) "
                 "или укажи --pretask ID")
    print("цепочка атак:", " → ".join(pt["attributes"]["taskName"] for pt in chain))

    bin_id, bin_ver = htp.newest_binary()
    print(f"cracker binary: id={bin_id} (hashcat {bin_ver})")

    if args.dry_run:
        ts = time.strftime("%Y%m%d-%H%M%S")
        for i, batch in enumerate(batches, 1):
            sample = batch[0].split("*")
            essid = sample[5] if len(sample) > 5 else "?"
            print(f"  батч {i}: {len(batch)} хешей, name={args.tag}-{ts}-{i:03d} "
                  f"(пример ESSID hex: {essid})")
        print("dry-run: ничего не отправлено")
        return

    # --- 3. отправка батчей ----------------------------------------------
    ts = time.strftime("%Y%m%d-%H%M%S")
    created: list[tuple[int, int, list[int]]] = []   # (hashlist_id, cracked_total, task_ids)
    for i, batch in enumerate(batches, 1):
        hl_name = f"{args.tag}-{ts}-{i:03d}"
        hl_id = htp.create_hashlist(hl_name, batch, args.access_group, args.note)
        task_ids = []
        for pt in chain:
            pt_name = pt["attributes"]["taskName"].replace("WPA2 | ", "").strip()
            tid = htp.create_task_from_pretask(
                pt, hl_id, bin_id, f"{hl_name} | {pt_name}")
            task_ids.append(tid)
        created.append((hl_id, len(batch), task_ids))
        print(f"  батч {i}: hashlist={hl_id} ({len(batch)} хешей), tasks={task_ids}")

    print()
    print(f"отправлено {len(created)} батч(ей), всего хешей: {sum(n for _, n, _ in created)}")
    print("прогресс/результаты: Web UI → Hashlists, или --wait")

    # --- 4. опциональное ожидание ----------------------------------------
    if not args.wait:
        return
    print()
    deadline = time.monotonic() + args.timeout if args.timeout else None
    prev: dict[int, int] = {}
    while True:
        all_done = True
        for hl_id, total, _tids in created:
            cracked, _ = htp.hashlist_state(hl_id)
            if cracked != prev.get(hl_id) or hl_id not in prev:
                print(f"[{time.strftime('%H:%M:%S')}] hashlist {hl_id}: {cracked}/{total}")
                prev[hl_id] = cracked
            if cracked < total:
                all_done = False
        if all_done:
            print("=== все хеши взяты ===")
            return
        if deadline and time.monotonic() > deadline:
            left = sum(1 for hl_id, total, _ in created if prev.get(hl_id, 0) < total)
            print(f"=== таймаут: {left} батч(ей) не докряканы ===")
            sys.exit(1)
        time.sleep(args.poll)


if __name__ == "__main__":
    main()
