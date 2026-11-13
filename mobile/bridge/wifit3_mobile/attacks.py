"""Campaign control: deauth / PMKID / WPS over the pinned upstream campaigns.

Upstream owns the radio rules (channel lease, PMF fallback, stop conditions); this
module adds session bookkeeping, a shared single-campaign slot (like the upstream
Campaign.active mutex) and DEMO shims with the same surface. The shims never import
upstream and never touch real radio hardware.
"""
from __future__ import annotations
import asyncio
import hashlib
import time
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def demo_capture_for(ssid: str, nonce: int) -> str:
    """A structurally valid synthetic hc22000 line for DEMO captures only.

    Deterministic per (ssid, nonce); the ESSID hex spells the fake network name so a
    leaked DEMO line can never be mistaken for a live capture. Never send it anywhere.
    """
    ssid_hex = f"DEMO-{ssid or 'hidden'}".encode().hex()
    seed = hashlib.sha256(f"{ssid}:{nonce}".encode()).hexdigest()
    mac = f"0200000000{seed[:2]}"        # locally administered, obviously synthetic
    return (f"WPA*01*{seed[:32]}*{mac}*{mac}*{ssid_hex}***")


class DemoAttack:
    """Demo twin of the upstream campaigns: same lifecycle surface, no radio."""
    def __init__(self, key, target_bssid, ssid, wps, on_capture):
        self.key = key
        self.target = type("T", (), {"bssid": target_bssid, "ssid": ssid, "channel": 6})()
        self.captured = False
        self.stopped = False
        self._on_capture = on_capture
        self._task = None
        self._steps, self._interval = {"deauth": (6, 0.5), "pmkid": (4, 0.5), "wps": (8, 0.5)}[key]
        if key == "deauth":
            self.client_sent = self.client_acks = self.bcast_sent = self.csa_sent = 0
        elif key == "pmkid":
            self.client_mac = "02:de:mo:00:00:01"
            self.attempts = 3                          # mirrors upstream PmkidHarvestAttack
            self.pmkid = None
            self.fail_reason = None
        else:
            self.status = "idle"                       # mirrors upstream WpsCampaign
            self.fail_reason = None
            self.state = type("S", (), {"found_pin": None, "found_psk": None,
                                        "phase": "common", "tested": 0, "attempts": 0})()
        self._wps = wps

    def run(self):
        self._task = asyncio.get_running_loop().create_task(self._loop())
        return True

    @property
    def done(self):
        return self._task is not None and self._task.done()

    def request_stop(self):
        self.stopped = True

    async def stop(self):
        self.stopped = True
        if self._task:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass

    def check_auto_stop(self):
        return False

    async def _loop(self):
        try:
            for i in range(self._steps):
                if self.stopped:
                    return
                await asyncio.sleep(self._interval)
                if self.key == "deauth":
                    self.client_sent += 2
                    self.client_acks += 1
                    self.bcast_sent += 2
                elif self.key == "pmkid":
                    pass
                else:
                    self.state.attempts += 1
                    self.state.tested += 1
                    self.status = "running"
            if self.stopped:
                return
            self.captured = True
            if self.key in ("deauth", "pmkid"):
                if self.key == "pmkid":
                    self.pmkid = b"\x01" * 16
                self._on_capture(self.target.bssid)    # synthetic hc22000 registered
            else:
                self.status = "found"
                self.state.phase = "done"
                self.state.found_pin = "12345670"      # obviously synthetic DEMO PIN
        except asyncio.CancelledError:
            raise


def _upstream_campaigns():
    """Campaign classes, keyed; raises ModuleNotFoundError without upstream (live mode)."""
    from wifit3.campaigns.deauth import DeauthCampaign
    from wifit3.campaigns.pmkid import PmkidHarvestAttack
    from wifit3.campaigns.pin import WpsCampaign
    return {"deauth": DeauthCampaign, "pmkid": PmkidHarvestAttack, "wps": WpsCampaign}


CAMPAIGN_LABELS = {"deauth": "Deauth: форсировать хендшейк",
                   "pmkid": "PMKID: собрать без клиентов",
                   "wps": "WPS PIN (включая Pixie Dust)"}


class CampaignControl:
    """One campaign slot per session; snapshot() feeds the API state."""
    def __init__(self, engine):
        self.engine = engine
        self.campaign = None
        self.key = None
        self.started_at = None
        self.error = ""
        self.last = None                      # summary of the most recent campaign
        self._watcher = None

    def reset(self):
        self.campaign = None
        self.key = None
        self.started_at = None
        self.error = ""
        self.last = None
        if self._watcher is not None:
            self._watcher.cancel()
            self._watcher = None

    @property
    def active(self):
        return self.campaign is not None and not self.campaign.done

    # ---- state -----------------------------------------------------------
    def _stats(self):
        campaign, key = self.campaign, self.key
        if campaign is None:
            return {}
        if key == "deauth":
            return {"client_sent": campaign.client_sent, "client_acks": campaign.client_acks,
                    "bcast_sent": campaign.bcast_sent, "csa_sent": campaign.csa_sent}
        if key == "pmkid":
            return {"attempts": campaign.attempts, "client_mac": campaign.client_mac,
                    "harvested": bool(campaign.pmkid)}
        state = campaign.state
        return {"tested": state.tested, "attempts": state.attempts, "phase": state.phase,
                "status": campaign.status}

    def _result(self, campaign, key):
        if key == "deauth":
            return {"captured": bool(campaign.captured)}
        if key == "pmkid":
            return {"harvested": bool(campaign.pmkid),
                    "fail": campaign.fail_reason.value if campaign.fail_reason else None}
        return {"pin": campaign.state.found_pin, "psk": campaign.state.found_psk,
                "status": campaign.status}

    def _headline(self):
        campaign, key = self.campaign, self.key
        if campaign is None:
            return "Кампания не запущена."
        if key == "deauth":
            if campaign.captured:
                return "● Новый крэкабельный захват получен — хеш доступен во вкладке «Хеши»."
            return ("● Deauth: форсируем повторный хендшейк · acks "
                    f"{campaign.client_acks}/{campaign.client_sent} · bcast {campaign.bcast_sent} · CSA {campaign.csa_sent}")
        if key == "pmkid":
            if campaign.pmkid:
                return "✓ PMKID получен — хеш добавлен во вкладку «Хеши»."
            if campaign.fail_reason:
                return f"✗ PMKID: {campaign.fail_reason.value}"
            return f"● PMKID: сбор (как {campaign.client_mac})"
        st = campaign.state
        if st.found_pin is not None:
            extra = f" · PSK получен: {st.found_psk}" if st.found_psk else ""
            return f"✓ WPS PIN найден: {st.found_pin}{extra}"
        if campaign.fail_reason:
            return f"✗ WPS: {campaign.fail_reason}"
        return f"● WPS PIN: {campaign.status} · фаза {st.phase} · проверено {st.tested}"

    def snapshot(self):
        campaign = self.campaign
        if campaign is None:
            last = dict(self.last) if self.last else None
            return {"active": False, "key": None, "bssid": "", "ssid": "", "captured": False,
                    "stats": {}, "headline": "Кампания не запущена.", "result": None,
                    "started_at": None, "error": self.error, "last": last}
        return {
            "active": self.active,
            "key": self.key,
            "bssid": campaign.target.bssid,
            "ssid": getattr(campaign.target, "ssid", "") or "",
            "captured": bool(campaign.captured or self._result(campaign, self.key).get(
                "harvested") or self._result(campaign, self.key).get("pin") is not None),
            "stats": self._stats(),
            "headline": self._headline(),
            "result": self._result(campaign, self.key),
            "started_at": self.started_at,
            "error": self.error,
            "last": dict(self.last) if self.last else None,
        }

    # ---- lifecycle -------------------------------------------------------
    async def start(self, key, bssid, authorized=None):
        if key not in CAMPAIGN_LABELS:
            raise ValueError("Неизвестная кампания.")
        if self.active:
            raise ValueError("Кампания уже выполняется. Сначала остановите текущую.")
        if self.engine.phase != "scanning":
            raise ValueError("Сначала запустите сканирование.")
        bssid = (bssid or "").strip().lower()
        if self.engine.demo:
            network = next((n for n in self.engine.networks if n["bssid"] == bssid), None)
            if network is None:
                raise ValueError("Сеть не найдена в DEMO-снимке.")
            if key in ("deauth", "pmkid") and not network.get("psk_family", False):
                raise ValueError(f"DEMO-цель не подходит для {key.upper()} (нужен WPA/WPA2-PSK).")
            if key == "wps" and not network.get("wps", False):
                raise ValueError("У DEMO-цели нет WPS.")
            campaign = DemoAttack(key, bssid, network["ssid"] or "", network.get("wps", False),
                                  self._demo_capture)
        else:
            campaign = self._live_campaign(key, bssid)
            # Upstream parity (Focus v2 _tune_to_target): a campaign only lands handshakes when the
            # pool stops hopping and holds the target's channel; otherwise EAPOL arrives off-channel.
            await self._tune_live(self.engine.array, campaign.target)
        self.campaign, self.key = campaign, key
        self.started_at, self.error, self.last = utcnow(), "", None
        campaign.run()
        if not self.engine.demo:
            self._watcher = asyncio.create_task(self._await_completion(campaign, key))
        self.engine.log(f"{key.upper()} запущен против " + bssid + (" (DEMO)" if self.engine.demo else ""))
        return self.snapshot()

    def _demo_capture(self, bssid):
        ssid = next((n["ssid"] for n in self.engine.networks if n["bssid"] == bssid), "")
        self.engine.register_demo_capture(bssid, demo_capture_for(ssid, time.time_ns()))
        self.engine.log("DEMO: синтетический захват записан для " + (ssid or bssid))

    def _live_campaign(self, key, bssid):
        """Build the upstream campaign; the class's own visible/ineligible gates decide."""
        array = self.engine.array
        if array is None:
            raise ValueError("Нет активной сессии приёма.")
        ap = array.access_points.get(bssid)
        if ap is None:
            raise ValueError("Сеть не найдена в текущем снимке. Обновите состояние.")
        classes = _upstream_campaigns()
        cls = classes[key]
        if not cls.visible(ap):
            raise ValueError(f"Цель не подходит для {CAMPAIGN_LABELS[key].split(':')[0]}.")
        reason = cls.ineligible_reason(ap)
        if reason:
            raise ValueError(f"Цель недоступна для {key.upper()}: {reason}.")
        return cls(array, ap, log=lambda m: self.engine.log(
            str(m).replace("[/]", "").replace("[", "").replace("]", "")))

    async def _tune_live(self, array, target):
        """Stop hopping and pin the pool to the target channel, like the upstream Focus screen."""
        try:
            await array.stop_hopping()
        except Exception as exc:
            self.engine.log("Не удалось остановить перебор каналов: " + str(exc))
        try:
            if not await array.set_channel(target.channel, scan=False):
                self.engine.log(f"Не удалось встать на канал {target.channel}; атака может быть глухой.")
            else:
                self.engine.log(f"Канал зафиксирован: {target.channel} (перебор приостановлен).")
        except Exception as exc:
            self.engine.log("Ошибка установки канала: " + str(exc))

    async def _restore_hopping(self):
        engine = self.engine
        if engine.demo or engine.phase != "scanning" or engine.array is None:
            return
        channels = getattr(engine, "_hop_channels", None)
        if not channels:
            return
        try:
            await engine.array.start_hopping(channels=channels, interval=engine._hop_interval)
            engine.log("Перебор каналов восстановлен.")
        except Exception as exc:
            engine.log("Не удалось восстановить перебор каналов: " + str(exc))

    async def _await_completion(self, campaign, key):
        """Auto-finish when the campaign stops on its own or reports done work (WPS)."""
        try:
            while not campaign.done:
                if campaign.check_auto_stop():
                    campaign.request_stop()
                await asyncio.sleep(0.3)
            if self.campaign is campaign:
                await self._finish(campaign, key, user_stop=False)
        except asyncio.CancelledError:
            raise

    async def _finish(self, campaign, key, user_stop):
        if getattr(campaign, "_bookkeeping_done", False):
            return
        campaign._bookkeeping_done = True
        result = self._result(campaign, key)
        self.last = {
            "key": key,
            "bssid": campaign.target.bssid,
            "ssid": getattr(campaign.target, "ssid", "") or "",
            "captured": bool(campaign.captured or result.get("harvested")
                             or result.get("pin") is not None),
            "result": result,
            "stats": self._stats() if self.campaign is campaign else {},
            "finished_at": utcnow(),
        }
        if key == "deauth":
            self.engine.log("Deauth: новый крэкабельный захват получен — цель "
                            + self.last["bssid"] if result["captured"]
                            else "Deauth завершён без нового захвата.")
        elif key == "pmkid":
            self.engine.log("PMKID получен." if result["harvested"]
                            else "PMKID не получен" + (f": {result['fail']}" if result["fail"] else "."))
        else:
            if result.get("pin") is not None:
                self.engine.log(f"WPS PIN найден: {result['pin']}"
                                + (f"; PSK: {result['psk']}" if result.get("psk") else ""))
            elif result.get("status") in ("failed", "error"):
                self.engine.log("WPS завершился неудачей: " + str(campaign.fail_reason))
            else:
                self.engine.log("WPS остановлен (PIN не найден на этот момент).")
        if self.campaign is campaign:
            self.campaign, self.key = None, None
        await self._restore_hopping()

    async def stop(self):
        campaign, key = self.campaign, self.key
        if campaign is None:
            return self.snapshot()
        try:
            await campaign.stop()
        except Exception as exc:
            self.error = f"Остановка кампании сообщила об ошибке: {exc}"
            self.engine.log(self.error)
        await self._finish(campaign, key, user_stop=True)
        return self.snapshot()

    async def close(self):
        """Session teardown: request a cooperative stop without awaiting the task."""
        if self._watcher is not None:
            self._watcher.cancel()
            self._watcher = None
        if self.campaign is not None:
            try:
                self.campaign.request_stop()
            except Exception:
                pass
            self.campaign, self.key = None, None
