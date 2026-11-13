"""Real subprocess integration. Loopback only, synthetic data, no Android/USB claims."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from urllib.parse import urlsplit
import pytest
from wifit3_mobile.service import control, read_info, call, healthy

@pytest.fixture
def service_dir(tmp_path,monkeypatch):
    # Child server must find this checkout even when the wheel isn't installed.
    root=str(Path(__file__).parents[1]/'bridge')
    monkeypatch.setenv('PYTHONPATH',root+os.pathsep+os.environ.get('PYTHONPATH',''))
    with socket.socket() as sock:
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:sock.bind(('127.0.0.1',8765))
        except OSError:pytest.skip('8765 occupied; never stop an unrelated server')
    yield tmp_path/'service'
    control('stop',tmp_path/'service')


def test_real_start_reuse_status_and_shutdown(service_dir):
    before=control('status',service_dir)
    assert before['status']=='stopped'
    started=control('start',service_dir,demo=True)
    assert started['protocol']=='wifit3-mobile/termux-v1' and started['status']=='running'
    url=urlsplit(started['url']);assert url.hostname=='127.0.0.1' and len(url.fragment)==43
    info=read_info(service_dir)
    assert (service_dir.stat().st_mode & 0o777)==0o700
    assert ((service_dir/'service.json').stat().st_mode & 0o777)==0o600
    same=control('start',service_dir,demo=True)
    assert same['url']==started['url'] and read_info(service_dir)['pid']==info['pid']
    assert control('status',service_dir)['url']==started['url']
    call(info,'refresh',{})
    call(info,'start',{'device_id':'demo','authorized':True})
    assert len(call(info,'state')['networks'])==4
    assert started['url'].split('#')[1] not in (service_dir/'service.log').read_text()
    assert control('stop',service_dir)['status']=='stopped'
    assert not (service_dir/'service.json').exists()
    assert not healthy(info)


def test_mode_change_requires_explicit_stop(service_dir):
    control('start',service_dir,demo=True)
    with pytest.raises(ValueError,match='другом режиме'):control('start',service_dir,demo=False)
    assert control('status',service_dir)['demo'] is True


def test_stop_is_idempotent_and_never_kills_from_stale_pid(service_dir):
    service_dir.mkdir()
    (service_dir/'service.json').write_text(json.dumps({'port':8765,'token':'a'*43,'instance_id':'stale','pid':os.getpid(),'demo':True}))
    assert control('stop',service_dir)['status']=='stopped'
    assert os.getpid()>0  # The test process was not signaled.
    started=control('start',service_dir,demo=True)
    assert started['status']=='running'
    assert control('stop',service_dir)['status']=='stopped'
    assert control('stop',service_dir)['status']=='stopped'


def test_cli_stdout_is_single_protocol_json(service_dir):
    result=subprocess.run([sys.executable,'-m','wifit3_mobile.service','status','--state-dir',str(service_dir)],capture_output=True,text=True,check=True)
    data=json.loads(result.stdout)
    assert data['status']=='stopped' and len(result.stdout.splitlines())==1


def test_port_conflict_does_not_touch_foreign_listener(service_dir):
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listener.bind(('127.0.0.1',8765));listener.listen()
        with pytest.raises(RuntimeError,match='порт 8765'):control('start',service_dir,demo=True)
        assert listener.getsockname()[1]==8765
