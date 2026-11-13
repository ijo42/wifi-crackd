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
    assert e.attack.snapshot()['captured'] is True
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
    assert e.attack.snapshot()['active'] is False
    assert e.snapshot()['hashes']['count'] == 0
    assert e.attack.snapshot()['last'] is None or e.attack.snapshot()['last']['captured'] in (True, False)


@pytest.mark.asyncio
async def test_demo_deauth_records_last_result():
    e = await started_engine()
    await e.start_deauth('02:00:00:00:00:02', True)
    await asyncio.sleep(3.5)
    await e.stop_deauth()
    last = e.attack.snapshot()['last']
    assert last is not None and last['captured'] is True and last['bssid'] == '02:00:00:00:00:02'
    await e.stop()


class _FakeArray:
    def __init__(self):
        self.calls = []
        self._channels = [1]

    async def stop_hopping(self):
        self.calls.append('stop_hopping')

    async def set_channel(self, channel, scan=False):
        self.calls.append(('set_channel', channel))
        return True

    async def start_hopping(self, channels=None, interval=0.5, **kw):
        self.calls.append(('start_hopping', tuple(channels), interval))


class _FakeEngine:
    def __init__(self):
        self.demo = False
        self.phase = 'scanning'
        self.array = _FakeArray()
        self._hop_channels = [1, 6, 11]
        self._hop_interval = 0.5
        self.loglines = []

    def log(self, message):
        self.loglines.append(str(message))


@pytest.mark.asyncio
async def test_live_tune_pins_channel_and_restore_hops_again():
    """Upstream parity: deauth must stop hopping and pin the target channel (EAPOL parity)."""
    from wifit3_mobile.attacks import CampaignControl
    engine = _FakeEngine()
    control = CampaignControl(engine)
    target = type('T', (), {'channel': 6})()
    await control._tune_live(engine.array, target)
    await control._restore_hopping()
    assert engine.array.calls[0] == 'stop_hopping'
    assert engine.array.calls[1] == ('set_channel', 6)
    assert engine.array.calls[2] == ('start_hopping', (1, 6, 11), 0.5)


@pytest.mark.asyncio
async def test_demo_pmkid_campaign_harvests_hash():
    e = await started_engine()
    await e.start_attack('pmkid', '02:00:00:00:00:01', True)
    await asyncio.sleep(2.4)                                    # pmkid shim settle (~2 s)
    snap = e.attack.snapshot()
    assert snap['captured'] is True and snap['result']['harvested'] is True
    assert e.snapshot()['hashes']['count'] == 1                 # demo PMKID registered as hc22000
    await e.stop()


@pytest.mark.asyncio
async def test_demo_wps_campaign_finds_pin_and_gates():
    e = await started_engine()
    with pytest.raises(ValueError):
        await e.start_attack('wps', '02:00:00:00:00:01', True)  # Studio/Lab has no WPS
    await e.start_attack('wps', '02:00:00:00:00:02', True)      # Home Network advertises WPS
    await asyncio.sleep(4.6)
    snap = e.attack.snapshot()
    assert snap['captured'] is True
    assert snap['result']['pin'] == '12345670'
    await e.stop()


@pytest.mark.asyncio
async def test_pmkid_snapshot_without_captured_attr():
    """Live PmkidHarvestAttack has no .captured — snapshot/result must not touch it."""
    from wifit3_mobile.attacks import CampaignControl
    engine = _FakeEngine()
    engine.phase = 'scanning'
    control = CampaignControl(engine)
    fake = type('F', (), {})()
    fake.target = type('T', (), {'bssid': '02:00:00:00:00:aa', 'ssid': 'x', 'channel': 6})()
    fake.attempts = 3
    fake.client_mac = '02:de:mo:00:00:01'
    fake.pmkid = b'\x01' * 16
    fake.fail_reason = None
    fake.done = True
    fake.stopped = True
    fake.check_auto_stop = lambda: False
    async def stop():
        pass
    fake.stop = stop
    control.campaign, control.key = fake, 'pmkid'
    snap = control.snapshot()
    assert snap['captured'] is True and snap['result']['harvested'] is True
    assert snap['stats']['harvested'] is True
    await control._finish(fake, 'pmkid', user_stop=True)
    assert control.last['captured'] is True and control.last['key'] == 'pmkid'
