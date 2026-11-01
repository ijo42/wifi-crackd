"""Ingest: безопасная распаковка архива, извлечение хэш-строк 22000.

Источники:
  .hc22000/.22000 — валидация по правилам wifit3 (crack/hc22000_format.py):
    WPA*01|02 = 9 полей, WPA*03|04 (FT) = 12 полей; MAC 12 hex, PMKID/MIC 32,
    ANONCE 64, ESSID ≤ 64 hex (≤32 байт), ESSID — hex utf-8.
  .pmkid/.16800 — конвертация 16800 → 22000 (WPA*01).
  .hccapx       — конвертация → 22000 (WPA*02).
  .pcap/.cap/.pcapng — hcxpcapngtool.
FT-строки (WPA*03/04) не брутятся hashcat -m 22000 — считаются отдельно (ft_count).
"""
from __future__ import annotations

import binascii
import re
import struct
import subprocess
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import config as cfg

ALLOWED_EXTENSIONS = {
    ".hc22000", ".22000", ".pmkid", ".16800",
    ".pcap", ".cap", ".pcapng", ".hccapx",
}

MAX_NAME_LEN = 200

# ---------------- валидатор 22000 ----------------

_HEX_RE = re.compile(r"[0-9a-fA-F]*")


def _is_hex(value: str, *, exact: int | None = None, maximum: int | None = None) -> bool:
    if not _HEX_RE.fullmatch(value):
        return False
    if len(value) % 2:
        return False
    if exact is not None and len(value) != exact:
        return False
    if maximum is not None and len(value) > maximum:
        return False
    return True


@dataclass
class HashLine:
    raw: str            # нормализованная строка (lowercase hex)
    kind: str           # "pmkid" | "eapol"
    bssid: str          # AA:BB:CC:DD:EE:FF (lowercase)
    ssid: str | None    # декодированный SSID или None (hidden)
    line: str           # строка для hashcat


def normalize_22000(line: str) -> str:
    """Нормализация hex-полей к lowercase (как wifit3 Hc22000Line)."""
    parts = line.split("*")
    if len(parts) not in (9, 12) or parts[0] != "WPA":
        return line
    out = [parts[0], parts[1]]
    for i, p in enumerate(parts[2:], start=2):
        out.append(p.lower() if _is_hex(p) else p)
    return "*".join(out)


def parse_22000(line: str) -> HashLine | None:
    """Валидация hc22000 по правилам wifit3/crack/hc22000_format.py."""
    parts = line.split("*")
    if len(parts) < 2 or parts[0] != "WPA":
        return None
    kind_code = parts[1]
    if kind_code not in ("01", "02", "03", "04"):
        return None
    is_ft = kind_code in ("03", "04")
    if is_ft != (len(parts) == 12):
        return None
    if kind_code == "01":
        # WPA*01*pmkid*ap*sta*essid***[mp]
        if not _is_hex(parts[2], exact=32):
            return None
    elif kind_code == "02":
        # WPA*02*mic*ap*sta*essid*anonce*eapol*mp
        if not _is_hex(parts[2], exact=32) or not _is_hex(parts[6], exact=64):
            return None
        if not _is_hex(parts[7]) or not (30 <= len(parts[7]) <= 1024):
            return None
    # 03/04 — FT: хэш-поля как в 01/02, валидатор пропускает только формат
    if not _is_hex(parts[3], exact=12) or not _is_hex(parts[4], exact=12):
        return None
    if not _is_hex(parts[5], maximum=64) or len(parts[5]) == 0:
        return None
    raw = normalize_22000(line)
    try:
        ssid = bytes.fromhex(parts[5]).decode("utf-8", errors="replace")
    except ValueError:
        return None
    bssid = ":".join(parts[3][i:i + 2] for i in range(0, 12, 2))
    return HashLine(
        raw=raw,
        kind="pmkid" if kind_code in ("01", "03") else "eapol",
        bssid=bssid,
        ssid=ssid or None,
        line=raw,
    )


# ---------------- конвертации ----------------

def parse_16800(line: str) -> HashLine | None:
    """16800: PMKID*AP*STA*ESSIDhex[:comments] → 22000 WPA*01."""
    main = line.split(":", 1)[0]
    parts = main.split("*")
    if len(parts) != 4:
        return None
    pmkid, ap, sta, essid_hex = parts
    if not _is_hex(pmkid, exact=32) or not _is_hex(ap, exact=12) or not _is_hex(sta, exact=12):
        return None
    if not _is_hex(essid_hex, maximum=64) or not essid_hex:
        return None
    out = f"WPA*01*{pmkid.lower()}*{ap.lower()}*{sta.lower()}*{essid_hex.lower()}***"
    hl = parse_22000(out)
    return hl


def parse_hccapx(data: bytes) -> list[HashLine]:
    """HCCAPX (несколько записей подряд) → 22000 WPA*02 строки."""
    lines: list[HashLine] = []
    offset = 0
    while True:
        idx = data.find(b"HCPX", offset)
        if idx < 0 or len(data) - idx < 11:
            break
        version = data[idx + 4]
        if version > 4:
            offset = idx + 4
            continue
        message_pair = data[idx + 5]
        mac_ap = data[idx + 6:idx + 12]
        nonce_ap = data[idx + 12:idx + 44]
        mac_sta = data[idx + 44:idx + 50]
        (eapol_len,) = struct.unpack_from("<H", data, idx + 50)
        eapol = data[idx + 52:idx + 52 + 256]
        essid_len = data[idx + 308]
        essid = data[idx + 309:idx + 309 + 32]
        mic = data[idx + 341:idx + 357]
        if eapol_len < 1 or eapol_len > 256 or essid_len > 32:
            offset = idx + 4
            continue
        eapol = eapol[:eapol_len]
        essid = essid[:essid_len]
        out = (
            f"WPA*02*{mic.hex()}*{mac_ap.hex()}*{mac_sta.hex()}*{essid.hex()}"
            f"*{nonce_ap.hex()}*{eapol.hex()}*{message_pair:02x}"
        )
        hl = parse_22000(out)
        if hl:
            lines.append(hl)
        offset = idx + 357
    return lines


# ---------------- сборка по файлам ----------------

@dataclass
class IngestResult:
    lines: list[HashLine] = field(default_factory=list)
    ft_count: int = 0
    n_files: int = 0
    errors: list[str] = field(default_factory=list)


def extract_from_file(path: Path, res: IngestResult) -> None:
    """Достаёт строки 22000 из одного файла (уже лежит на диске)."""
    ext = path.suffix.lower()
    try:
        if ext in (".hc22000", ".22000"):
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                kind_code = raw.split("*", 2)[1] if raw.startswith("WPA*0") and raw.count("*") >= 2 else ""
                if kind_code in ("03", "04"):
                    # FT (802.11r) — hashcat -m 22000 их не брутит, считаем отдельно
                    hl = parse_22000(raw)
                    if hl:
                        res.ft_count += 1
                    continue
                hl = parse_22000(raw)
                if hl:
                    res.lines.append(hl)
        elif ext in (".pmkid", ".16800"):
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if raw:
                    hl = parse_16800(raw)
                    if hl:
                        res.lines.append(hl)
        elif ext == ".hccapx":
            res.lines.extend(parse_hccapx(path.read_bytes()))
        elif ext in (".pcap", ".cap", ".pcapng"):
            out = _run_hcxpcapngtool(path)
            if out is not None:
                for raw in out.splitlines():
                    raw = raw.strip()
                    if raw:
                        hl = parse_22000(raw)
                        if hl:
                            res.lines.append(hl)
        # неизвестные расширения сюда не попадают (whitelist при распаковке)
    except (OSError, ValueError) as exc:
        res.errors.append(f"{path.name}: {exc}")


def _run_hcxpcapngtool(pcap: Path) -> str | None:
    """hcxpcapngtool -o out.22000; возвращает содержимое или None."""
    with tempfile.TemporaryDirectory(prefix="crackd-hcx-") as tmp:
        out = Path(tmp) / "out.22000"
        try:
            proc = subprocess.run(
                [cfg.HCXPCAPNGTOOL, "-o", str(out), str(pcap)],
                capture_output=True, timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"hcxpcapngtool failed: {exc}") from None
        if proc.returncode not in (0, 1) or not out.is_file():
            # rc=1 — «вульгарные» ошибки hcxtool при частичном извлечении
            return None
        try:
            return out.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None


# ---------------- zip ----------------

def _safe_zip_name(name: str) -> str | None:
    """Валидация имени внутри архива (zip-slip): плоское имя, whitelist расширений."""
    if not name or len(name) > MAX_NAME_LEN:
        return None
    p = Path(name.replace("\\", "/"))
    if p.is_absolute() or any(part in ("..", "") for part in p.parts):
        return None
    ext = p.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return None
    return name


def unpack_zip(zip_bytes: bytes, limits_max_files: int, limits_max_mb: int) -> list[Path]:
    """Безопасная распаковка: ограничения по количеству/объёму, случайные имена на диске."""
    import io

    max_total = limits_max_mb * 1024 * 1024
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError("не zip-архив") from exc

    infos = [i for i in zf.infolist() if not i.is_dir()]
    if len(infos) > limits_max_files:
        raise ValueError(f"слишком много файлов в архиве ({len(infos)} > {limits_max_files})")
    if sum(i.file_size for i in infos) > max_total:
        raise ValueError("суммарный размер содержимого превышает лимит")

    cfg.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    job_dir = cfg.UPLOAD_DIR / uuid.uuid4().hex[:16]
    job_dir.mkdir(parents=True)

    saved: list[Path] = []
    for info in infos:
        name = _safe_zip_name(info.filename)
        if name is None:
            continue
        if info.file_size > max_total:
            raise ValueError("файл внутри архива превышает лимит")
        dest = job_dir / (uuid.uuid4().hex[:12] + Path(name).suffix.lower())
        with zf.open(info) as src, open(dest, "wb") as dst:
            remaining = max_total
            while chunk := src.read(1024 * 512):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ValueError("zip-bomb: содержимое больше заявленного")
                dst.write(chunk)
        saved.append(dest)
    return saved


def ingest_zip(zip_bytes: bytes, limits_max_files: int, limits_max_mb: int) -> IngestResult:
    """Полная приёмка: распаковка + извлечение + дедуп. Бросает ValueError с человекочитаемой причиной."""
    files = unpack_zip(zip_bytes, limits_max_files, limits_max_mb)
    res = IngestResult(n_files=len(files))
    seen: set[str] = set()
    for f in files:
        extract_from_file(f, res)
    unique: list[HashLine] = []
    for hl in res.lines:
        if hl.raw in seen:
            continue
        seen.add(hl.raw)
        unique.append(hl)
    res.lines = unique
    return res


def targets_of(lines: list[HashLine]) -> list[dict]:
    """[{ssid,bssid,kind,count}] по dedup-строкам (для карточки в админке)."""
    agg: dict[tuple, dict] = {}
    for hl in lines:
        key = (hl.ssid, hl.bssid, hl.kind)
        if key in agg:
            agg[key]["count"] += 1
        else:
            agg[key] = {"ssid": hl.ssid, "bssid": hl.bssid, "kind": hl.kind, "count": 1}
    return list(agg.values())
