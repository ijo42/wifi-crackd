from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from wifit3_mobile.observation import DisconnectObservations


def rx(kind='deauth',protected=False):
    # Synthetic parsed RX record, not a transmitted frame.
    return SimpleNamespace(type=kind,raw=b'\x00\x40' if protected else b'',
        bssid='02:00:00:00:00:01',source='02:00:00:00:00:01',dest='ff:ff:ff:ff:ff:ff',rssi=-42,reason=7)


def test_received_kinds_and_protected_reason():
    o=DisconnectObservations()
    o.receive(rx('beacon'));o.receive(rx());o.receive(rx('disassoc',True))
    state=o.snapshot()
    assert state['counts']=={'deauth':1,'disassoc':1}
    assert state['events'][0]['reason']==7
    assert state['events'][1]['reason'] is None and state['events'][1]['protected'] is True
    assert state['events'][0]['destination']=='ff:ff:ff:ff:ff:ff'


def test_bounded_rx_ring_thread_safe_and_copied():
    o=DisconnectObservations(limit=150)
    with ThreadPoolExecutor(4) as pool:list(pool.map(lambda _:o.receive(rx()),range(2000)))
    state=o.snapshot()
    assert state['counts']['deauth']==2000 and len(state['events'])==150
    assert state['events'][-1]['observation_id']==2000
    state['events'][0]['reason']='modified'
    assert o.snapshot()['events'][0]['reason']==7


def test_engine_state_contains_passive_rx_log():
    from wifit3_mobile.engine import Engine
    e=Engine(demo=True);e.disconnect_observations.receive(rx())
    assert e.snapshot()['disconnect_observations']['counts']['deauth']==1
    assert e.snapshot()['passive_only'] is False
    assert e.snapshot()['audit'] is True
