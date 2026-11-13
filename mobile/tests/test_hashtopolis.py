"""Hashtopolis stdlib client against a local stub server. No real Hashtopolis, no external traffic."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

from wifit3_mobile import hashtopolis

PRETASKS = [
    {"id": "1", "attributes": {"taskName": "WPA2 | dict router-defaults", "attackCmd": "#hl# -a 0 #h# #d1#",
                               "priority": 0, "crackerBinaryTypeId": 1, "chunkTime": 600}},
    {"id": "2", "attributes": {"taskName": "WPA2 | rule OneRule x router-defaults", "attackCmd": "#hl# -a 0 #h# #d1# -r #d2#",
                               "priority": 5, "crackerBinaryTypeId": 1}},
    {"id": "3", "attributes": {"taskName": "WPA2 | mask RU mobile 8-9xx", "attackCmd": "#hl# -a 3 #h# #m#",
                               "priority": None, "crackerBinaryTypeId": 1}},
    {"id": "9", "attributes": {"taskName": "MD5 | dict", "attackCmd": "#hl# -a 0 #h# #d1#", "crackerBinaryTypeId": 1}},
]


class Stub(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def _reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authed(self):
        return self.headers.get("Authorization", "") in ("Bearer jwt-1", "Bearer static-1")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"null")
        if self.path == "/api/v2/auth/token":
            if payload != ["role.all"]:
                return self._reply(400, {"error": "bad role request"})
            return self._reply(201, {"token": "jwt-1"})
        if not self._authed():
            return self._reply(401, {"error": "unauthorized"})
        if self.path == "/api/v2/ui/hashlists":
            self.server.requests.append(("hashlist", payload["data"]["attributes"]["hashCount"],
                                         payload["data"]["attributes"]["sourceData"]))
            return self._reply(200, {"data": {"id": 50 + len(self.server.requests)}})
        if self.path == "/api/v2/ui/tasks":
            self.server.requests.append(("task", payload["data"]["attributes"]["hashlistId"],
                                         payload["data"]["attributes"]["priority"]))
            return self._reply(200, {"data": {"id": 900 + len(self.server.requests)}})
        return self._reply(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/api/v2/ui/pretasks?page%5Bsize%5D=10000":
            if not self._authed():
                return self._reply(401, {"error": "unauthorized"})
            if getattr(self.server, "fail_big_page", False):
                # newer Hashtopolis: oversized page[size] is a malformed request
                return self._reply(400, {"title": "Malformed request", "status": 400,
                                         "type": "about:blank"})
            return self._reply(200, {"data": PRETASKS})
        if self.path.startswith("/api/v2/ui/pretasks?") and "page%5Bnumber%5D" in self.path:
            if not self._authed():
                return self._reply(401, {"error": "unauthorized"})
            from urllib.parse import parse_qs, urlsplit
            qs = parse_qs(urlsplit(self.path).query)
            number = int(qs.get("page[number]", ["1"])[0])
            data = getattr(self.server, "paged_pretasks", None) or PRETASKS
            chunk = data[(number - 1) * 100:number * 100]
            return self._reply(200, {"data": chunk})
        if self.path == "/api/v2/ui/crackers":
            return self._reply(200, {"data": [{"id": 7, "attributes": {"version": "6.2.1"}},
                                              {"id": 8, "attributes": {"version": "8.1.2"}}]})
        if self.path.startswith("/api/v2/ui/pretasks/") and self.path.endswith("/pretaskFiles"):
            return self._reply(200, {"data": [{"id": "11"}, {"id": "12"}]})
        if self.path.startswith("/api/v2/ui/hashlists/"):
            return self._reply(200, {"data": {"attributes": {"cracked": 3, "hashCount": 5}}})
        return self._reply(404, {"error": "not found"})


@pytest.fixture
def stub_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
    server.requests = []
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server
    server.shutdown()
    server.server_close()


def client(url, **kw):
    return hashtopolis.HashtopolisClient(url, user="admin", password="pw", timeout=10, **kw)


def test_login_and_verify(stub_url):
    url, _server = stub_url
    assert client(url).verify() == {"ok": True, "pretasks": 4}


def test_static_token_used_directly(stub_url):
    url, _server = stub_url
    c = hashtopolis.HashtopolisClient(url, token="static-1", timeout=10)
    assert c.verify()["ok"] is True


def test_newest_binary_picks_highest_version(stub_url):
    url, _server = stub_url
    assert client(url).newest_binary() == (8, "8.1.2")


def test_select_pretasks_modes():
    default = hashtopolis.select_pretasks(PRETASKS)
    assert [pt["id"] for pt in default] == ["1", "2", "3"]          # DEFAULT_CHAIN substrings, in order
    all_wpa = hashtopolis.select_pretasks(PRETASKS, all_wpa=True)
    assert [pt["id"] for pt in all_wpa] == ["1", "2", "3"]
    explicit = hashtopolis.select_pretasks(PRETASKS, wanted_ids=[9])
    assert [pt["id"] for pt in explicit] == ["9"]
    with pytest.raises(hashtopolis.HashtopolisError):
        hashtopolis.select_pretasks(PRETASKS, wanted_ids=[42])


def test_create_hashlist_and_tasks(stub_url):
    url, server = stub_url
    c = client(url)
    pt = hashtopolis.select_pretasks(PRETASKS, wanted_ids=[1])[0]
    hl = c.create_hashlist("hs-test", ["WPA*01*a"], 1, "note")
    tid = c.create_task_from_pretask(pt, hl, 8, "name")
    assert hl == 51 and tid == 902
    kinds = [r[0] for r in server.requests]
    assert kinds == ["hashlist", "task"]
    import base64
    stored = base64.b64decode(server.requests[0][2]).decode()
    assert stored == "WPA*01*a"
    assert server.requests[1][2] == 1                                # priority forced to >= 1


def test_hashlist_state(stub_url):
    url, _server = stub_url
    assert client(url).hashlist_state(5) == (3, 5)


def test_bad_login_reports_error(stub_url):
    url, _server = stub_url
    with pytest.raises(hashtopolis.HashtopolisError):
        hashtopolis.HashtopolisClient(url, user="admin", password="pw")._call(
            "POST", "/api/v2/auth/token", ["wrong"])


def test_config_roundtrip_and_masking(tmp_path):
    hashtopolis.save_config(tmp_path, url="http://htp.example", token="t0ken", user="admin")
    assert hashtopolis.load_config(tmp_path)["token"] == "t0ken"
    hashtopolis.save_config(tmp_path, url="http://htp.example", user="admin")   # no token → dropped
    assert "token" not in hashtopolis.load_config(tmp_path)
    hashtopolis.clear_config(tmp_path)
    assert hashtopolis.load_config(tmp_path) == {}


def test_pretasks_pagination_fallback_on_400(stub_url):
    """Newer Hashtopolis rejects page[size]=10000; the client must fall back to pages."""
    url, server = stub_url
    server.fail_big_page = True
    server.paged_pretasks = PRETASKS
    assert client(url).pretasks() == PRETASKS


def test_pretasks_pagination_multiple_pages(stub_url):
    url, server = stub_url
    server.fail_big_page = True
    big = [dict(PRETASKS[i % len(PRETASKS)], id=str(i + 1)) for i in range(250)]
    server.paged_pretasks = big
    got = client(url).pretasks()
    assert len(got) == 250 and got[0]["id"] == "1" and got[-1]["id"] == "250"
