"""hc22000 collection helpers + DEMO pipeline. Live serialisation is upstream's own (tested there)."""
import pytest
from wifit3_mobile import hashes as hashcollect
from wifit3_mobile.engine import Engine


def test_summarize_unique_and_batches():
    per = {'aa:aa': ['L2', 'L1'], 'bb:bb': ['L3']}      # collectors dedup per network already
    assert hashcollect.summarize(per) == {'count': 3, 'networks': {'aa:aa': 2, 'bb:bb': 1}}
    assert hashcollect.unique_lines(per) == ['L2', 'L1', 'L3']
    assert hashcollect.batches(list('abcdef'), 4) == [list('abcd'), list('ef')]
    assert hashcollect.batches(['x'], 0) == [['x']]          # clamped
    assert hashcollect.batches(['x'], 99_999) == [['x']]     # clamped


def test_demo_collection_only_captured_networks():
    e = Engine(demo=True)
    assert hashcollect.collect_demo(e) == {}
    e.register_demo_capture('02:00:00:00:00:02', 'WPA*01*aabb*aabb*aabb*414243***')
    per = hashcollect.collect_demo(e)
    assert hashcollect.summarize(per)['count'] == 1
    assert e.snapshot()['hashes']['count'] == 1


def test_demo_hash_lines_flow_into_engine():
    e = Engine(demo=True)
    e.register_demo_capture('02:00:00:00:00:02', 'WPA*01*ccdd*ccdd*ccdd*444555***')
    assert e.hash_lines() == ['WPA*01*ccdd*ccdd*ccdd*444555***']


def test_empty_state_has_no_hashes():
    e = Engine(demo=True)
    assert e.snapshot()['hashes'] == {'count': 0, 'networks': {}}
    assert e.hash_lines() == []
