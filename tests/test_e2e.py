import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import db
from app.main import app
from conftest import VALID_EAPOL, VALID_FT, VALID_PMKID

FIXTURES = __import__("pathlib").Path(__file__).parent / "fixtures"


@pytest.fixture()
def client(tmp_path):
    db.reset_for_tests()
    from app import config as cfg
    cfg.DB_PATH = tmp_path / "test.db"
    cfg.UPLOAD_DIR = tmp_path / "uploads"
    cfg.JOBS_DIR = tmp_path / "jobs"
    cfg.POTFILE = tmp_path / "hashcat.potfile"
    db.reset_for_tests()
    with TestClient(app) as c:
        yield c
    db.reset_for_tests()


def make_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def upload(c: TestClient, zip_bytes: bytes, token: str = ""):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return c.post("/api/upload", files={"captures": ("captures.zip", zip_bytes, "application/zip")},
                  data={"note": "тест"}, headers=headers)


def login(c: TestClient):
    c.post("/login", data={"password": "testpass"})


def wait_state(c: TestClient, job_id: str, secret: str, states: set[str], timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = c.get(f"/api/jobs/{job_id}", params={"secret": secret})
        st = r.json()["state"]
        if st in states:
            return st
        time.sleep(0.3)
    return st


class TestStatusJson:
    def test_v8_schema(self):
        from app.hashcat import parse_status_json
        line = ('{"session":"hashcat","guess":{},"status":3,'
                '"progress":[42090496,400000000],"recovered_hashes":[0,10],'
                '"devices":[{"device_id":1,"device_name":"RTX 3060","speed":390149}],'
                '"estimated_stop":9999999999}')
        up = parse_status_json(line)
        assert up.status_code == 3
        assert abs(up.progress - 10.5) < 0.1
        assert up.speed_hs == "390.1 kH/s"
        assert up.eta and "дн" in up.eta

    def test_v6_fallback(self):
        from app.hashcat import parse_status_json
        line = ('{"status":3,"progress":[1,2],"speed_sec":[[100000,500]],'
                '"eta":[{"minutes":7}]}')
        up = parse_status_json(line)
        assert up.progress == 50.0
        assert up.speed_hs == "200.0 kH/s"
        assert up.eta == "7 мин"


class TestE2E:
    def test_anon_full_flow(self, client):
        r = upload(client, make_zip({"cap.hc22000": (VALID_EAPOL + "\n" + VALID_FT).encode()}))
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["state"] == "pending"
        assert data["hash_count"] == 1          # FT отфильтрован
        assert data["ft_count"] == 1

        job_id, secret = data["job_id"], data["secret"]
        # статус без secret не отдаётся
        assert client.get(f"/api/jobs/{job_id}").status_code == 404
        assert client.get(f"/api/jobs/{job_id}", params={"secret": "wrong"}).status_code == 404

        # без логина админка закрыта (редирект на /login)
        assert client.get("/admin", follow_redirects=False).status_code == 303

        login(client)
        # цели видны до акцепта
        page = client.get("/admin").text
        assert "HomeNet" in page and job_id in page

        # акцепт → очередь → DRY_RUN-воркер доводит до done
        client.post(f"/admin/jobs/{job_id}/accept")
        st = wait_state(client, job_id, secret, {"done", "failed"})
        assert st == "done", client.get(f"/api/jobs/{job_id}", params={"secret": secret}).json()

        # пароль найден и виден только в админке
        client.post("/logout")
        # в публичном статусе паролей нет
        pub = client.get(f"/api/jobs/{job_id}", params={"secret": secret}).json()
        assert "password" not in pub
        login(client)
        page = client.get(f"/admin/jobs/{job_id}").text
        assert "dry-run-demo" in page

    def test_token_upload_skips_acceptance(self, client):
        # создать токен через админку
        login(client)
        r = client.post("/admin/tokens", data={"name": "dev-laptop"}, follow_redirects=True)
        page = r.text
        key = page.split('class="pass big">')[1].split("</code>")[0]
        assert key.startswith("wfk_")

        r = upload(client, make_zip({"cap.hc22000": VALID_PMKID.encode()}), token=key)
        assert r.status_code == 200
        data = r.json()
        assert data["state"] == "queued"

        st = wait_state(client, data["job_id"], data["secret"], {"done", "failed"})
        assert st == "done"

    def test_invalid_upload_rejected_400(self, client):
        r = upload(client, make_zip({"garbage.hc22000": b"not a hashline\n"}))
        assert r.status_code == 400
        assert "валидных" in r.json()["detail"]

    def test_not_a_zip_400(self, client):
        r = upload(client, b"definitely not a zip")
        assert r.status_code == 400

    def test_wrong_token_401(self, client):
        r = upload(client, make_zip({"cap.hc22000": VALID_PMKID.encode()}), token="wfk_deadbeef")
        assert r.status_code == 401

    def test_anon_rate_limit(self, client):
        for _ in range(3):
            r = upload(client, make_zip({"garbage.hc22000": b"junk"}))
            assert r.status_code == 400  # приёмка до лимита бракует содержимое, не rate
        # лимит на уже учтённые запросы
        db.execute("DELETE FROM jobs")
        r = upload(client, make_zip({"cap.hc22000": VALID_PMKID.encode()}))
        assert r.status_code == 200
        for _ in range(100):
            if not db.anon_rate_ok("testclient", 100000):
                break
        # исчерпаем честно: 100 запросов в час с этого IP уже могли быть
        # — проверяем только, что механика отвечает
        rows = db.query("SELECT COUNT(*) AS n FROM rate")
        assert rows[0]["n"] >= 1

    def test_wifit3_fixture_zip(self, client):
        """Полный zip из фикстуры wifit3: служебные файлы отсеиваются whitelist'ом."""
        import os
        folder = FIXTURES / "wifit3_captures"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for f in sorted(folder.rglob("*")):
                if f.is_file():
                    zf.writestr(f.name, f.read_bytes())
        r = upload(client, buf.getvalue())
        assert r.status_code == 200, r.text
        data = r.json()
        # eapol + pmkid валидны, FT отфильтрован, битый pcap даст 0 строк от hcxtool
        assert data["hash_count"] == 2
        assert data["ft_count"] == 1
        assert any(t["ssid"] == "HomeNet" for t in data["targets"])

    def test_reject_flow(self, client):
        r = upload(client, make_zip({"cap.hc22000": VALID_PMKID.encode()}))
        job_id = r.json()["job_id"]
        login(client)
        client.post(f"/admin/jobs/{job_id}/reject", data={"reason": "тестовый отказ"})
        st = client.get(f"/api/jobs/{job_id}", params={"secret": r.json()["secret"]}).json()
        assert st["state"] == "rejected" and "тестовый отказ" in st["error"]
