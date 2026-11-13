"""Authenticated loopback HTTP API; stdlib only. Never listen on a LAN address."""
from __future__ import annotations
import argparse
import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import signal
import threading
from urllib.parse import urlsplit

from . import hashes as hashcollect
from . import __version__
from .engine import Engine

STATIC = Path(__file__).with_name("static")
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


def make_handler(engine, loop, token, port, shutdown_event=None):
    host = f"127.0.0.1:{port}"
    origin = f"http://{host}"

    class Handler(BaseHTTPRequestHandler):
        # Do not log URL fragments, API headers, SSIDs or token values.
        def log_message(self, *_):
            pass

        def reply(self, status, payload, content_type="application/json; charset=utf-8"):
            if not isinstance(payload, bytes):
                payload = json.dumps(payload, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def allowed(self, api=False):
            if self.headers.get("Host") != host:
                self.reply(403, {"error": "Invalid Host"})
                return False
            if self.headers.get("Origin") not in (None, origin):
                self.reply(403, {"error": "Cross-origin requests denied"})
                return False
            if api and not secrets.compare_digest(self.headers.get("Authorization", "").encode("utf-8"), f"Bearer {token}".encode("utf-8")):
                self.reply(401, {"error": "Нужен код подключения из Termux."})
                return False
            return True

        def run_async(self, coro):
            future = asyncio.run_coroutine_threadsafe(coro, loop)
            try:
                return future.result(timeout=130)
            except FutureTimeout:
                # An operation can still be in flight. Client must refresh state, not auto-retry.
                raise RuntimeError("Операция ещё выполняется. Проверьте состояние, не повторяйте запуск.")

        def do_GET(self):
            path = urlsplit(self.path).path
            if not self.allowed(api=path.startswith("/api/")):
                return
            if path in ASSETS:
                filename, mime = ASSETS[path]
                return self.reply(200, (STATIC / filename).read_bytes(), mime)
            if path == "/api/state":
                async def state():
                    return engine.snapshot()
                try:
                    return self.reply(200, self.run_async(state()))
                except Exception as exc:
                    return self.reply(500, {"error": str(exc)})
            if path == "/api/hashes":
                try:
                    return self.reply(200, {"demo": engine.demo,
                                            **hashcollect.summarize(engine._refresh_hashes()),
                                            "lines": engine.hash_lines()})
                except Exception as exc:
                    return self.reply(500, {"error": str(exc)})
            self.reply(404, {"error": "Not found"})

        def do_POST(self):
            if not self.allowed(api=True):
                return
            if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                return self.reply(415, {"error": "JSON required"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 16384:
                    return self.reply(413, {"error": "Body limit: 16384 bytes"})
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError("JSON object required")
                path = urlsplit(self.path).path
                if path == "/api/refresh":
                    data = self.run_async(engine.refresh())
                elif path == "/api/start":
                    if body.get("authorized") is not True:
                        raise ValueError("Подтвердите право на аудит оборудования.")
                    data = self.run_async(engine.start(body.get("device_id"), body.get("band", "all")))
                elif path == "/api/stop":
                    data = self.run_async(engine.stop())
                elif path == "/api/attack/start":
                    data = self.run_async(engine.start_attack(
                        body.get("campaign"), body.get("bssid"), body.get("authorized")))
                elif path == "/api/attack/all":
                    data = self.run_async(engine.start_attack_all(
                        body.get("campaign"), body.get("authorized")))
                elif path == "/api/attack/stop":
                    data = self.run_async(engine.stop_attack())
                elif path == "/api/deauth/start":      # legacy alias (pre-0.4.2 clients)
                    data = self.run_async(engine.start_deauth(body.get("bssid"), body.get("authorized")))
                elif path == "/api/deauth/stop":
                    data = self.run_async(engine.stop_deauth())
                elif path == "/api/hashes/send":
                    data = self.run_async(engine.hashtopolis_send(
                        url=body.get("url", ""), token=body.get("token", ""),
                        user=body.get("user", ""), password=body.get("password", ""),
                        batch=body.get("batch", 250), access_group=body.get("access_group", 1),
                        tag=body.get("tag", "hs-mobile"), note=str(body.get("note", ""))[:300],
                        pretask_ids=body.get("pretask_ids"), all_wpa=bool(body.get("all_wpa", False)),
                        dry_run=bool(body.get("dry_run", False))))
                elif path == "/api/htp":
                    if body.get("clear") is True:
                        data = engine.htp_clear()
                    else:
                        data = engine.htp_save(body.get("url", ""), token=str(body.get("token", "")),
                                               user=str(body.get("user", "")))
                elif path == "/api/htp/test":
                    data = self.run_async(engine.hashtopolis_test(
                        url=body.get("url", ""), token=body.get("token", ""),
                        user=body.get("user", ""), password=body.get("password", "")))
                elif path == "/api/hashes/status":
                    data = self.run_async(engine.hashtopolis_status(
                        url=body.get("url", ""), token=body.get("token", ""),
                        user=body.get("user", ""), password=body.get("password", "")))
                elif path == "/api/shutdown" and shutdown_event is not None:
                    async def shutdown():
                        await engine.stop()
                        shutdown_event.set()
                        return {"status": "stopping"}
                    data = self.run_async(shutdown())
                else:
                    return self.reply(404, {"error": "Not found"})
                self.reply(200, data)
            except (ValueError, TypeError, json.JSONDecodeError) as exc:
                self.reply(400, {"error": str(exc)})
            except Exception as exc:
                engine.log(str(exc))
                self.reply(500, {"error": str(exc)})
    return Handler


async def serve(port, demo, token_file=None, service_info=None, state_dir=None):
    if state_dir is None:
        if service_info:
            # Managed mode: keep htp.json next to service.json in the same 0700 directory.
            state_dir = str(Path(service_info).parent)
        else:
            state_dir = os.environ.get("WIFIT3_MOBILE_STATE",
                                       str(Path.home() / ".local" / "share" / "wifit3-mobile"))
    engine = Engine(demo=demo, state_dir=state_dir)
    loop = asyncio.get_running_loop()
    token = secrets.token_urlsafe(32)
    engine.instance_id = secrets.token_hex(16)
    stopped = asyncio.Event()
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(engine, loop, token, port, stopped))
    if service_info:
        info_path = Path(service_info)
        info_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = info_path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump({"token": token, "instance_id": engine.instance_id, "pid": os.getpid(), "port": port, "demo": demo}, stream)
        os.replace(temporary, info_path)
    server.daemon_threads = True
    if token_file:
        # Test/automation opt-in; not used by normal startup.
        path = Path(token_file)
        path.touch(mode=0o600, exist_ok=True)
        path.chmod(0o600)
        path.write_text(token)
    print(f"Wifit3 Mobile {'DEMO (synthetic data)' if demo else '(passive survey)'}", flush=True)
    if not service_info:
        print(f"Open locally: http://127.0.0.1:{port}/#{token}", flush=True)
        print(f"Connection code: {token}\nDo not share the code. Ctrl+C stops reception.", flush=True)
    else:
        print("Managed local service ready; credentials are kept in private storage.", flush=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stopped.set)
        except NotImplementedError:
            # Windows event loops have no add_signal_handler; Ctrl+C still unwinds via KeyboardInterrupt.
            pass
    try:
        await stopped.wait()
    finally:
        await engine.stop()
        await asyncio.to_thread(server.shutdown)
        server.server_close()
        if token_file:
            Path(token_file).unlink(missing_ok=True)
        if service_info:
            try:
                current = json.loads(Path(service_info).read_text())
                if current.get("instance_id") == engine.instance_id:
                    Path(service_info).unlink(missing_ok=True)
            except (OSError, ValueError):
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--demo", action="store_true", help="Synthetic data, no USB imports or radio use")
    parser.add_argument("--token-file", help=argparse.SUPPRESS)
    parser.add_argument("--service-info", help=argparse.SUPPRESS)
    parser.add_argument("--state-dir", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Port must be between 1024 and 65535")
    try:
        asyncio.run(serve(args.port, args.demo, args.token_file, args.service_info, args.state_dir))
    except OSError as exc:
        parser.exit(1, f"Cannot start local service: {exc}\n")


if __name__ == "__main__":
    main()
