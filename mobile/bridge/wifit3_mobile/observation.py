"""Bounded passive RX observations. Never constructs or transmits radio frames."""
from collections import deque
from datetime import datetime, timezone
from threading import Lock


class DisconnectObservations:
    """Counters are received observations, not unique frames or proof of an attack.

    An RX-thread-safe bounded event ring avoids per-frame asyncio task creation.
    Protected management bodies are deliberately not interpreted as plaintext reasons.
    """
    def __init__(self, limit=150):
        self._lock = Lock()
        self._events = deque(maxlen=limit)
        self._total = {"deauth": 0, "disassoc": 0}
        self._sequence = 0

    def receive(self, packet):
        kind = getattr(packet, "type", None)
        if kind not in ("deauth", "disassoc"):
            return
        raw = getattr(packet, "raw", b"")
        protected = bool(len(raw) >= 2 and raw[1] & 0x40)
        event = {
            "time": datetime.now(timezone.utc).isoformat(), "type": kind,
            "bssid": packet.bssid, "source": packet.source, "destination": packet.dest,
            "signal": packet.rssi, "protected": protected,
            "reason": None if protected else getattr(packet, "reason", None),
        }
        with self._lock:
            self._sequence += 1
            event["observation_id"] = self._sequence
            self._total[kind] += 1
            self._events.append(event)

    def snapshot(self):
        with self._lock:
            return {"counts": dict(self._total), "events": [dict(e) for e in self._events],
                    "retained_limit": self._events.maxlen,
                    "meaning": "RX observations, may include retries; not proof of attack or sender identity"}
