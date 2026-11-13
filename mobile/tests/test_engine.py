import asyncio
import pytest
from wifit3_mobile.engine import Engine

@pytest.mark.asyncio
async def test_demo_lifecycle():
    e=Engine(demo=True)
    assert e.snapshot()['networks']==[]
    await e.refresh()
    state=await e.start('demo','all')
    assert state['phase']=='starting'
    await asyncio.sleep(0)
    assert e.snapshot()['phase']=='scanning'
    assert len(e.snapshot()['networks'])==4
    state=await e.stop()
    assert state['phase']=='idle' and len(state['networks'])==4
    assert not state['devices'][0]['active']

@pytest.mark.asyncio
@pytest.mark.parametrize('band,count',[('2g',3),('5g',1)])
async def test_demo_bands(band,count):
    e=Engine(demo=True)
    await e.refresh();await e.start('demo',band);await asyncio.sleep(0)
    assert len(e.snapshot()['networks'])==count
    await e.stop()

@pytest.mark.asyncio
async def test_reject_invalid_state_and_ids():
    e=Engine(demo=True)
    with pytest.raises(ValueError): await e.start('absent','all')
    await e.refresh()
    with pytest.raises(ValueError): await e.start('demo','bogus')
    await e.start('demo','all')
    with pytest.raises(ValueError): await e.start('demo','all')
    await e.stop()

@pytest.mark.asyncio
async def test_cancel_start():
    e=Engine(demo=True)
    await e.refresh();await e.start('demo','all');await e.stop()
    assert e.phase=='idle' and e._connect_task is None

@pytest.mark.asyncio
async def test_bounded_logs():
    e=Engine(demo=True)
    for i in range(1000): e.log(i)
    assert len(e.snapshot()['logs'])==150
