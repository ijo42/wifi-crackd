"""Engine-level Hashtopolis flow: dry-run, DEMO send block, config via HTTP API and CLI."""
import asyncio
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
import pytest

from wifit3_mobile.engine import Engine
from test_hashtopolis import Stub, client  # reuse the stub server and client helper


@pytest.fixture
def stub_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    server.requests = []
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server
    server.shutdown()
    server.server_close()


@pytest.mark.asyncio
async def test_demo_blocks_real_send_but_allows_dry_run(stub_url):
    url, server = stub_url
    e = Engine(demo=True)
    with pytest.raises(ValueError, match="нет"):
        await e.hashtopolis_send(url=url)                       # no hashes yet
    e.register_demo_capture('02:00:00:00:00:02', 'WPA*01*aabb*aabb*aabb*414243***')
    with pytest.raises(ValueError, match="DEMO"):
        await e.hashtopolis_send(url=url)                       # real send blocked in DEMO
    plan = await e.hashtopolis_send(url=url, dry_run=True)
    assert plan == {"dry_run": True, "url": url, "total": 1,
                    "batches": [{"name_hint": 1, "count": 1}]}
    assert server.requests == []                                # nothing left the device


@pytest.mark.asyncio
async def test_engine_send_against_stub_server(stub_url):
    url, server = stub_url
    e = Engine(demo=False)                                      # send gate is demo-only
    e._hash_cache = {'02:00:00:00:00:02': [f'WPA*01*{i:016x}*a*a*414243***' for i in range(3)]}
    e.state_dir = None
    result = await e.hashtopolis_send(url=url, user="admin", password="pw",
                                      batch=2, access_group=1, note="n", pretask_ids=[1])
    assert result["total"] == 3 and result["hashcat"] == "8.1.2"
    assert [b["count"] for b in result["batches"]] == [2, 1]    # batched by 2
    assert len(server.requests) == 4                            # 2 hashlists + 2 tasks (chain of 1)
    assert result["chain"] == ["WPA2 | dict router-defaults"]


def _pick_free_port():
    probe = ThreadingHTTPServer(("127.0.0.1", 0), ThreadingHTTPServer)
    port = probe.server_address[1]
    probe.server_close()
    return port


@pytest.fixture
def api_server(tmp_path):
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    engine = Engine(demo=True, state_dir=str(tmp_path))
    server = ThreadingHTTPServer(('127.0.0.1', 0), lambda *args: None)
    port = server.server_address[1]
    from wifit3_mobile.server import make_handler
    server.RequestHandlerClass = make_handler(engine, loop, 'test-token', port)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    def request(method, path, body=None, headers=None):
        h = {'Host': f'127.0.0.1:{port}', 'Authorization': 'Bearer test-token',
             'Content-Type': 'application/json'}
        h.update(headers or {})
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=h)
        response = conn.getresponse()
        data = response.read()
        out = (response.status, json.loads(data) if data else None)
        conn.close()
        return out
    yield request, engine
    asyncio.run_coroutine_threadsafe(engine.stop(), loop).result(3)
    server.shutdown()
    server.server_close()
    loop.call_soon_threadsafe(loop.stop)
    t.join()
    loop.close()


def test_htp_config_api_saves_masks_and_clears(api_server, tmp_path):
    request, engine = api_server
    assert request('POST', '/api/htp', {'url': 'https://htp.example', 'user': 'admin',
                                        'token': 'sekret'})[0] == 200
    status, state = request('GET', '/api/state')
    assert status == 200 and state['htp']['url'] == 'https://htp.example'
    assert state['htp']['has_token'] is True and state['htp']['submitted'] == []
    stored = json.loads((tmp_path / 'htp.json').read_text())
    assert stored['token'] == 'sekret'                          # private 0600 file keeps it
    assert request('POST', '/api/htp', {'clear': True})[0] == 200
    assert request('GET', '/api/state')[1]['htp']['has_token'] is False


def test_htp_config_api_rejects_bad_url(api_server):
    request, _engine = api_server
    assert request('POST', '/api/htp', {'url': 'notaurl'})[0] == 400


def test_deauth_endpoints(api_server):
    request, _engine = api_server
    request('POST', '/api/refresh', {})
    request('POST', '/api/start', {'device_id': 'demo', 'authorized': True})
    assert request('POST', '/api/deauth/start', {'bssid': '02:00:00:00:00:02'})[0] == 400   # no consent
    assert request('POST', '/api/deauth/start',
                   {'bssid': '02:00:00:00:00:02', 'authorized': True})[0] == 200
    assert request('POST', '/api/deauth/start',
                   {'bssid': '02:00:00:00:00:02', 'authorized': True})[0] == 400         # busy
    assert request('POST', '/api/deauth/stop', {})[0] == 200
    request('POST', '/api/stop', {})


def test_hashes_endpoints(api_server):
    request, engine = api_server
    assert request('GET', '/api/hashes') == (200, {'demo': True, 'count': 0, 'networks': {}, 'lines': []})
    engine.register_demo_capture('02:00:00:00:00:02', 'WPA*01*aabb*aabb*aabb*414243***')
    status, data = request('GET', '/api/hashes')
    assert status == 200 and data['count'] == 1 and data['lines'][0].startswith('WPA*')
    assert request('POST', '/api/hashes/send', {'url': 'http://x', 'dry_run': True})[0] == 200
    assert request('POST', '/api/hashes/send', {'url': 'http://x'})[0] == 400               # DEMO block


def test_htp_cli(tmp_path, capsys, monkeypatch):
    from wifit3_mobile import htp_cli
    argv = ['--state-dir', str(tmp_path), 'set', '--url', 'https://htp.example', '--token', 'tkn']
    monkeypatch.setattr('sys.argv', ['wifit3-mobile-htp'] + argv)
    htp_cli.main()
    argv = ['--state-dir', str(tmp_path), 'show']
    monkeypatch.setattr('sys.argv', ['wifit3-mobile-htp'] + argv)
    htp_cli.main()
    out = capsys.readouterr().out
    assert 'https://htp.example' in out and 'tkn' not in out    # token masked in show
    monkeypatch.setattr('sys.argv', ['wifit3-mobile-htp', '--state-dir', str(tmp_path), 'clear'])
    htp_cli.main()
    assert not (tmp_path / 'htp.json').exists()


@pytest.mark.asyncio
async def test_send_books_submission_and_status_updates(stub_url):
    """Regression (0.4.6): send stores hashlists for tracking; status polls cracked/total."""
    url, server = stub_url
    e = Engine(demo=False)
    e._hash_cache = {'02:00:00:00:00:02': ['WPA*01*0011*a*a*414243***']}
    result = await e.hashtopolis_send(url=url, user="admin", password="pw",
                                      batch=10, pretask_ids=[1])
    state = e.htp_state()
    assert state['submitted'] == [{'hashlist': result['batches'][0]['hashlist'],
                                   'name': result['batches'][0]['name'],
                                   'count': 1, 'tasks': result['batches'][0]['tasks'],
                                   'cracked': 0, 'total': 1}]
    assert state['last']['url'] == url and state['last']['hashcat'] == '8.1.2'
    status = await e.hashtopolis_status(url=url, user="admin", password="pw")
    assert status['submitted'][0]['cracked'] == 3 and status['submitted'][0]['total'] == 5
    assert e.htp_state()['submitted'][0]['cracked'] == 3   # persisted in engine state


@pytest.mark.asyncio
async def test_status_with_no_submission_is_empty(stub_url):
    url, _server = stub_url
    e = Engine(demo=False)
    assert await e.hashtopolis_status(url=url, user="admin", password="pw") == \
        {"submitted": [], "cracked": 0, "total": 0}
