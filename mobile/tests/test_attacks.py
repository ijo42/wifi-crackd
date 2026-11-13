"""DEMO deauth lifecycle. Live upstream TX is exercised by upstream's own tests; no radio here."""
import asyncio
import pytest
from wifit3_mobile.attacks import demo_capture_for
from wifit3_mobile.engine import Engine


async def started_engine():
    e = Engine(demo=True)
    await e.refresh()
    await e.start('demo', 'all')
    await asyncio.sleep(0)
    return e


@pytest.mark.asyncio
async def test_demo_capture_line_is_synthetic_and_structured():
    line = demo_capture_for('Home Network', 1)
    parts = line.split('*')
    assert parts[0] == 'WPA' and parts[1] == '01'
    assert bytes.fromhex(parts[5]).decode().startswith('DEMO-')   # ESSID marked as fake
    assert all(len(p) % 2 == 0 for p in parts[2:6])               # hex fields


@pytest.mark.asyncio
async def test_deauth_requires_consent_and_session():
    e = Engine(demo=True)
    with pytest.raises(ValueError):
        await e.start_deauth('02:00:00:00:00:01', None)
    await e.refresh()
    with pytest.raises(ValueError):
        await e.start_deauth('02:00:00:00:00:01', True)            # not scanning


@pytest.mark.asyncio
async def test_demo_deauth_lifecycle_and_capture():
    e = await started_engine()
    bssid = '02:00:00:00:00:02'                                    # WPA2 demo network
    state = await e.start_deauth(bssid, True)
    assert state['deauth']['active'] is True and state['deauth']['bssid'] == bssid
    assert state['phase'] == 'scanning'                            # full state contract
    with pytest.raises(ValueError):
        await e.start_deauth('02:00:00:00:00:01', True)            # one target at a time
    await asyncio.sleep(3.5)                                       # demo shim settle (~3 s)
    assert e.deauth.snapshot()['captured'] is True
    hashes = e.snapshot()['hashes']
    assert hashes['count'] == 1 and hashes['networks'][bssid] == 1
    assert e.hash_lines()[0].startswith('WPA*01*')
    stopped = await e.stop_deauth()
    assert stopped['deauth']['active'] is False
    await e.stop()


@pytest.mark.asyncio
async def test_deauth_rejects_open_and_absent_targets():
    e = await started_engine()
    with pytest.raises(ValueError):
        await e.start_deauth('02:00:00:00:00:99', True)            # absent bssid
    with pytest.raises(ValueError):
        await e.start_deauth('02:00:00:00:00:04', True)            # OPEN demo network
    await e.stop()


@pytest.mark.asyncio
async def test_stop_resets_deauth_and_session_stop_stops_campaign():
    e = await started_engine()
    await e.start_deauth('02:00:00:00:00:02', True)
    await e.stop()
    assert e.deauth.snapshot()['active'] is False
    assert e.snapshot()['hashes']['count'] == 0
