"""Hashtopolis REST client, stdlib only (no new Termux dependencies).

Same v2/ui endpoints as the wifisend client, reduced to what hash submission needs:
auth (long-lived API token or short-lived JWT from user/password), pretask listing,
cracker binary pick, hashlist paste + pretask-clone tasks, cracked-ratio polling.

Passwords and JWTs are never persisted; the optional long-lived API token may be
kept in the private 0600 state file via save_config/clear_token below.
"""
from __future__ import annotations
import base64
import json
import os
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

# дефолтная эскалационная цепочка — подстроки имён pretask'ов сервера (как в wifisend)
DEFAULT_CHAIN = (
    "dict router-defaults",
    "rule OneRule x router-defaults",
    "dict ru-phone-round",
    "mask 8 digits",
    "mask RU mobile 8-9xx",
)


class HashtopolisError(RuntimeError):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def config_path(state_dir) -> Path:
    return Path(state_dir).expanduser() / "htp.json"


def load_config(state_dir) -> dict:
    try:
        data = json.loads(config_path(state_dir).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(state_dir, *, url, user="", token=""):
    """Persist url/user and an optional long-lived API token; private dir, 0600 file."""
    path = config_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    payload = {"url": url.rstrip("/"), "user": user}
    if token:
        payload["token"] = token
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(payload, stream)
    os.replace(temporary, path)


def clear_config(state_dir):
    config_path(state_dir).unlink(missing_ok=True)


class HashtopolisClient:
    def __init__(self, url, token="", user="", password="", timeout=60):
        self.url = url.rstrip("/")
        self._static = (token or "").strip() or None
        self._user = (user or "").strip() or None
        self._password = password or None
        self._jwt = None
        self.timeout = timeout

    # ---- transport ------------------------------------------------------
    def _call(self, method, path, payload=None, retry_auth=True):
        headers = {"Content-Type": "application/json"}
        token = self._static or self._jwt
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(payload).encode() if payload is not None else None
        req = urlrequest.Request(f"{self.url}{path}", data=data, headers=headers, method=method)
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as response:
                body = response.read()
                status = response.status
        except urlerror.HTTPError as exc:
            body, status = exc.read(), exc.code
        except urlerror.URLError as exc:
            raise HashtopolisError(f"Сервер Hashtopolis недоступен: {exc.reason}") from exc
        if status == 401 and retry_auth and not self._static:
            self._jwt = self._login()
            return self._call(method, path, payload, retry_auth=False)
        try:
            parsed = json.loads(body) if body else {}
        except ValueError:
            parsed = {}
        if status >= 400:
            snippet = str(parsed or body[:200])[:300]
            raise HashtopolisError(f"{method} {path} -> HTTP {status}: {snippet}", status=status)
        return parsed

    def _login(self):
        if not self._user:
            raise HashtopolisError("Нет ни API-токена, ни пользователя для входа.")
        req = urlrequest.Request(
            f"{self.url}/api/v2/auth/token",
            data=json.dumps(["role.all"]).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=self.timeout) as response:
                if response.status != 201:
                    raise HashtopolisError(f"Логин отклонён (HTTP {response.status}).", status=response.status)
                return json.loads(response.read())["token"]
        except urlerror.HTTPError as exc:
            raise HashtopolisError(f"Логин {self._user!r} отклонён (HTTP {exc.code}): "
                                   f"{exc.read()[:150]!r}", status=exc.code) from exc

    # ---- domain ---------------------------------------------------------
    def verify(self):
        """Cheap authed call used by the UI 'test connection' button."""
        tasks = self.pretasks()
        return {"ok": True, "pretasks": len(tasks)}

    def pretasks(self):
        """All server pretasks. Newer Hashtopolis builds reject page[size]=10000 with
        HTTP 400 (Malformed request) — fall back to numbered 100-per-page pagination."""
        try:
            return self._call("GET", "/api/v2/ui/pretasks?page%5Bsize%5D=10000")["data"]
        except HashtopolisError as exc:
            if exc.status != 400:
                raise
        out, page = [], 1
        while True:
            data = self._call("GET", f"/api/v2/ui/pretasks"
                                     f"?page%5Bsize%5D=100&page%5Bnumber%5D={page}")["data"]
            out.extend(data)
            if len(data) < 100:
                return out
            page += 1

    def newest_binary(self):
        data = self._call("GET", "/api/v2/ui/crackers")["data"]
        if not data:
            raise HashtopolisError("На сервере нет cracker binary — залей hashcat-бинарник.")
        best = max(data, key=lambda d: tuple(map(int, d["attributes"]["version"].split("."))))
        return int(best["id"]), best["attributes"]["version"]

    def pretask_file_ids(self, pretask_id):
        rel = self._call("GET", f"/api/v2/ui/pretasks/{pretask_id}/pretaskFiles")
        return [int(d["id"]) for d in rel.get("data", [])]

    def create_hashlist(self, name, lines, access_group, note):
        b64 = base64.b64encode("\n".join(lines).encode()).decode()
        resp = self._call("POST", "/api/v2/ui/hashlists", {"data": {
            "type": "hashlist",
            "attributes": {
                "sourceType": "paste", "sourceData": b64, "name": name,
                "format": 0, "hashTypeId": 22000, "hashCount": len(lines),
                "isSecret": False, "isHexSalt": False, "isSalted": False,
                "accessGroupId": access_group, "notes": note,
                "useBrain": False, "brainFeatures": 0, "isArchived": False,
            },
        }})
        hl_id = resp.get("data", {}).get("id")
        if not hl_id:
            raise HashtopolisError(f"hashlist не создан: {str(resp)[:200]}")
        return int(hl_id)

    def create_task_from_pretask(self, pretask, hashlist_id, binary_id, name):
        a = pretask["attributes"]
        resp = self._call("POST", "/api/v2/ui/tasks", {"data": {
            "type": "task",
            "attributes": {
                "hashlistId": hashlist_id,
                "files": self.pretask_file_ids(int(pretask["id"])),
                "taskName": name,
                "attackCmd": a["attackCmd"],
                "chunkTime": a.get("chunkTime", 600),
                "statusTimer": a.get("statusTimer", 5),
                # fixed 1: zero-priority tasks are invisible to agents (see wifisend README)
                "priority": max(1, a.get("priority") or 1),
                "maxAgents": a.get("maxAgents", 0),
                "isSmall": bool(a.get("isSmall", False)),
                "isCpuTask": bool(a.get("isCpuTask", False)),
                "useNewBench": bool(a.get("useNewBench", True)),
                "skipKeyspace": 0,
                "crackerBinaryId": binary_id,
                "crackerBinaryTypeId": a.get("crackerBinaryTypeId"),
                "isArchived": False,
                "notes": f"pretask#{pretask['id']}",
                "staticChunks": 0,
                "chunkSize": a.get("chunkSize", 600),
                "forcePipe": bool(a.get("forcePipe", False)),
                "preprocessorId": a.get("preprocessorId", 0),
                "preprocessorCommand": a.get("preprocessorCommand", ""),
                "color": "",
            },
        }})
        tid = resp.get("data", {}).get("id")
        if not tid:
            raise HashtopolisError(f"task не создан: {str(resp)[:200]}")
        return int(tid)

    def hashlist_state(self, hashlist_id):
        attrs = self._call("GET", f"/api/v2/ui/hashlists/{hashlist_id}")["data"]["attributes"]
        return int(attrs.get("cracked") or 0), int(attrs.get("hashCount") or 0)


def select_pretasks(server_pretasks, wanted_ids=None, all_wpa=False):
    """Pick the attack chain: explicit ids, all 'WPA2 |' pretasks, or DEFAULT_CHAIN names."""
    if wanted_ids:
        wanted = {int(i) for i in wanted_ids}
        chain = [pt for pt in server_pretasks if int(pt["id"]) in wanted]
        missing = wanted - {int(pt["id"]) for pt in chain}
        if missing:
            raise HashtopolisError(f"pretask(и) не найдены на сервере: {sorted(missing)}")
        return chain
    if all_wpa:
        return [pt for pt in server_pretasks if pt["attributes"]["taskName"].startswith("WPA2 |")]
    chain = [pt for pt in server_pretasks
             if any(s in pt["attributes"]["taskName"] for s in DEFAULT_CHAIN)]
    if not chain:
        raise HashtopolisError("На сервере нет подходящих pretask'ов — создай их или укажи id явно.")
    return chain
