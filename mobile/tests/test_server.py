import asyncio
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
import pytest
from wifit3_mobile.engine import Engine
from wifit3_mobile.server import make_handler

@pytest.fixture
def api_server():
    loop=asyncio.new_event_loop()
    t=threading.Thread(target=loop.run_forever,daemon=True);t.start()
    engine=Engine(demo=True)
    server=ThreadingHTTPServer(('127.0.0.1',0),lambda *args:None)
    port=server.server_address[1]
    server.RequestHandlerClass=make_handler(engine,loop,'test-token',port)
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    def request(method,path,body=None,headers=None):
        h={'Host':f'127.0.0.1:{port}','Authorization':'Bearer test-token','Content-Type':'application/json'}
        h.update(headers or {})
        conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        conn.request(method,path,body=json.dumps(body) if body is not None else None,headers=h)
        response=conn.getresponse();data=response.read();out=(response.status,data,dict(response.getheaders()));conn.close();return out
    yield request
    asyncio.run_coroutine_threadsafe(engine.stop(),loop).result(3)
    server.shutdown();server.server_close();loop.call_soon_threadsafe(loop.stop);t.join();loop.close()

@pytest.mark.parametrize('headers,status',[
 ({'Authorization':''},401),({'Authorization':'Bearer wrong'},401),
 ({'Host':'evil.example'},403),({'Origin':'https://evil.example'},403)])
def test_api_access_controls(api_server,headers,status):
    assert api_server('GET','/api/state',headers=headers)[0]==status

def test_assets_and_no_cache(api_server):
    status,body,headers=api_server('GET','/')
    assert status==200 and 'Wifit3 Mobile' in body.decode()
    assert headers['X-Frame-Options']=='DENY' and headers['Cache-Control']=='no-store'
    assert "script-src 'self'" in headers['Content-Security-Policy']

def test_api_lifecycle_and_consent(api_server):
    assert api_server('POST','/api/refresh',{})[0]==200
    assert api_server('POST','/api/start',{'device_id':'demo'})[0]==400
    assert api_server('POST','/api/start',{'device_id':'demo','authorized':True})[0]==200
    assert api_server('POST','/api/stop',{})[0]==200

def test_routes_and_content_type(api_server):
    assert api_server('GET','/missing')[0]==404
    assert api_server('GET','/../../engine.py')[0]==404
    assert api_server('POST','/api/stop',{},headers={'Content-Type':'text/plain'})[0]==415
