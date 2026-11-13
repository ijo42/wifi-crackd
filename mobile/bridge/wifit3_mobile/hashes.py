"""hc22000 collection: live from the upstream sink, synthetic in DEMO.

Live lines come from upstream's own serialisers (eapol_hashlines / pmkid_hashline),
so the output matches what wifit3 writes on disk. Hashcat-crackable FT pairs are
emitted as WPA*04 by upstream; hashcat -m 22000 ignores them, Hashtopolis stores
them harmlessly. Hidden SSIDs yield no lines: without the ESSID hashcat cannot crack.
"""
from __future__ import annotations


def collect_from_array(array) -> dict[str, list[str]]:
    """{bssid: [hc22000 lines]} for every visible AP of a live session.

    RX threads mutate ap.handshakes concurrently; dict() copies are taken before
    iterating and a racing mutation is retried once rather than crashing a poll.
    """
    from wifit3.crack.hc22000_format import eapol_hashlines, pmkid_hashline
    out: dict[str, list[str]] = {}
    for ap in list(array.access_points.values()):
        ssid = ap.ssid or ""
        if not ssid:
            continue
        lines: list[str] = []
        try:
            handshakes = list(dict(ap.handshakes).items())
        except (RuntimeError, TypeError):
            try:
                handshakes = list(dict(ap.handshakes).items())
            except Exception:
                continue
        for _client, hs in handshakes:
            lines.extend(eapol_hashlines(ssid, hs))
            pmkid = pmkid_hashline(ssid, hs)
            if pmkid:
                lines.append(pmkid)
        if lines:
            out[ap.bssid] = sorted(set(lines))
    return out


def collect_demo(engine) -> dict[str, list[str]]:
    """{bssid: [lines]} from DEMO captures registered by the demo campaign shims."""
    return {bssid: list(lines) for bssid, lines in engine.demo_captures.items()}


def summarize(per_network: dict[str, list[str]]) -> dict:
    networks = {bssid: len(lines) for bssid, lines in per_network.items()}
    return {"count": sum(networks.values()), "networks": networks}


def unique_lines(per_network: dict[str, list[str]]) -> list[str]:
    seen, ordered = set(), []
    for lines in per_network.values():
        for line in lines:
            if line not in seen:
                seen.add(line)
                ordered.append(line)
    return ordered


def batches(lines: list[str], size: int) -> list[list[str]]:
    size = max(1, min(int(size or 250), 2000))
    return [lines[i:i + size] for i in range(0, len(lines), size)]
