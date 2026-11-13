"""Runs when the pinned upstream is installed/on PYTHONPATH. No radio or USB used."""
import pytest
pytest.importorskip('wifit3')
from wifit3.wlan.array import WlanArray
from wifit3.dot11.packet import BeaconPacket
from wifit3_mobile.engine import serialize_ap


def test_real_upstream_beacon_to_mobile_json():
    array=WlanArray()
    sink=array._sink
    sink.update(BeaconPacket(type='beacon',type_id=0,subtype_id=8,
        bssid='02:00:00:00:00:01',source='02:00:00:00:00:01',dest='ff:ff:ff:ff:ff:ff',
        to_ds=False,from_ds=False,rssi=-47,raw=b'',ssid='Laboratory',channel=6,encryption='WPA2'), 'wlan0')
    data=serialize_ap(list(array.access_points.values())[0], array.clients)
    assert data['ssid']=='Laboratory' and data['signal']==-47
    assert data['channel']==6 and data['beacons']==1 and data['clients']==[]


def test_real_upstream_rx_parser_to_passive_observer():
    from wifit3.dot11.parser import WlanFrameParser
    from wifit3_mobile.observation import DisconnectObservations
    # Fixed receive-only fixture, no radio device or TX APIs are used.
    fixture=bytes.fromhex('c0000000ffffffffffff02000000000102000000000110000700')
    packet=WlanFrameParser.parse_80211_frame(fixture,rssi=-51)
    assert packet.type=='deauth' and packet.reason==7
    observations=DisconnectObservations();observations.receive(packet)
    event=observations.snapshot()['events'][0]
    assert event['bssid']=='02:00:00:00:00:01' and event['reason']==7 and event['signal']==-51


@pytest.mark.asyncio
async def test_engine_wires_rx_callback_without_transmission(monkeypatch):
    import asyncio
    from wifit3_mobile.engine import Engine
    import wifit3.device.manager as manager
    import wifit3.wlan.array as array_module
    from types import SimpleNamespace
    callbacks=[]
    class ReceiveInterface:
        supported_channels=[1,6,11]
        async def connect(self,**kwargs):return True
        def register_rx_callback(self,callback):callbacks.append(callback)
        async def close(self):pass
    class ReceiveArray:
        access_points={};clients={}
        def register_disconnect_callback(self,callback):pass
        def attach(self,iface):pass
        async def start_hopping(self,**kwargs):pass
        async def close(self):pass
    monkeypatch.setattr(manager,'wlan_iface',lambda d:ReceiveInterface())
    monkeypatch.setattr(array_module,'WlanArray',ReceiveArray)
    e=Engine();e.devices=[{'id':'fixture'}];e._device_map={'fixture':object()}
    await e.start('fixture','2g');await asyncio.sleep(0)
    assert len(callbacks)==1 and e.phase=='scanning'
    callbacks[0](SimpleNamespace(type='deauth',raw=b'',bssid='02:00:00:00:00:01',source='02:00:00:00:00:01',dest='ff:ff:ff:ff:ff:ff',rssi=-45,reason=3))
    assert e.snapshot()['disconnect_observations']['counts']['deauth']==1
    await e.stop()
    assert len(e.snapshot()['disconnect_observations']['events'])==1
    await e.start('fixture','2g');await asyncio.sleep(0)
    assert e.snapshot()['disconnect_observations']['counts']['deauth']==0
    await e.stop()
