"""Fixed-command Termux lifecycle controller. JSON stdout is consumed by Android.

No arbitrary commands, shell evaluation, external URL, or PID-based killing.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import time
from urllib.error import URLError, HTTPError
from urllib.request import Request, build_opener, ProxyHandler

from . import __version__

PROTOCOL = "wifit3-mobile/termux-v1"
PORT = 8765


def private_directory(path):
    path = Path(path).expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def read_info(directory):
    try:
        info = json.loads((directory / "service.json").read_text())
        if (not isinstance(info, dict) or info.get("port") != PORT
                or not isinstance(info.get("token"), str) or len(info["token"]) != 43
                or not isinstance(info.get("instance_id"), str) or not isinstance(info.get("demo"), bool)):
            return None
        return info
    except (OSError, ValueError, KeyError):
        return None


def call(info, route, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = Request(f"http://127.0.0.1:{PORT}/api/{route}", data=data,
                      headers={"Authorization": "Bearer " + info["token"],
                               "Content-Type": "application/json"})
    # Android-local traffic must never go through an environment proxy.
    with build_opener(ProxyHandler({})).open(request, timeout=2) as response:
        return json.load(response)


def healthy(info):
    if not info:
        return False
    try:
        state = call(info, "state")
        return state.get("instance_id") == info["instance_id"]
    except (OSError, ValueError, HTTPError, URLError):
        return False


def port_occupied():
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=0.3):
            return True
    except OSError:
        return False


def result(action, status, info=None):
    data = {"protocol": PROTOCOL, "version": __version__, "action": action, "status": status}
    if info:
        data.update(demo=bool(info["demo"]),
                    url=f"http://127.0.0.1:{PORT}/#{info['token']}")
    return data


def control(action, directory, demo=False):
    if action not in ("start", "status", "stop"):
        raise ValueError("Unsupported service action")
    directory = private_directory(directory)
    # Serializes simultaneous clicks/processes; start/status are idempotent.
    try:
        import fcntl
    except ImportError as exc:
        raise RuntimeError("Управляемый сервис поддерживает только POSIX (Termux/Linux): нет fcntl.") from exc
    with (directory / "control.lock").open("a+") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        info = read_info(directory)
        running = healthy(info)
        if not running and port_occupied():
            raise RuntimeError("Неизвестный процесс занял порт 8765 (возможно, ручной запуск). Остановите его самостоятельно в Termux или подключитесь вручную по коду. Чужой процесс не остановлен.")
        if action == "status":
            return result(action, "running" if running else "stopped", info if running else None)
        if action == "stop":
            if not running:
                return result(action, "stopped")
            call(info, "shutdown", {})
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                current = read_info(directory)
                if not current or current.get("instance_id") != info["instance_id"]:
                    return result(action, "stopped")
                time.sleep(0.1)
            raise RuntimeError("Остановка ещё не подтверждена. Проверьте Termux; не завершайте чужие процессы.")
        if running:
            if bool(info["demo"]) != demo:
                raise ValueError("Модуль работает в другом режиме. Сначала остановите модуль, затем выберите нужный режим.")
            return result(action, "running", info)
        command = [sys.executable, "-m", "wifit3_mobile.server", "--service-info", str(directory / "service.json")]
        if demo:
            command.append("--demo")
        # FD + environment inherited by the venv Python, never a shell command from a client.
        log_path = directory / "service.log"
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.chmod(log_path, 0o600)
        with os.fdopen(fd, "wb") as logfile:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=logfile,
                                       stderr=logfile, start_new_session=True, close_fds=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            info = read_info(directory)
            if healthy(info):
                return result(action, "running", info)
            if process.poll() is not None:
                raise RuntimeError("Не удалось запустить модуль. Возможно, порт 8765 занят ручным запуском. Проверьте private service.log в Termux; чужой процесс не остановлен.")
            time.sleep(0.1)
        raise RuntimeError("Модуль не подтвердил готовность. Проверьте статус в Termux перед повторным запуском.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("action", choices=("start", "status", "stop"))
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--state-dir", default=str(Path.home()/".local/share/wifit3-mobile/service"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        payload = control(args.action, args.state_dir, args.demo)
    except Exception as exc:
        print(json.dumps({"protocol": PROTOCOL, "action": args.action, "status": "error", "error": str(exc)}, ensure_ascii=False), flush=True)
        return 1
    print(json.dumps(payload, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
