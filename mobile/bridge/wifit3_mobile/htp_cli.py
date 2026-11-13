"""wifit3-mobile-htp: Hashtopolis config for the local module, from the terminal.

Writes the same private 0600 htp.json the server reads, so the URL/token can be
set once over SSH/adb and the UI picks it up. The token is never printed back.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import __version__
from . import hashtopolis

DEFAULT_STATE_DIR = str(Path.home() / ".local" / "share" / "wifit3-mobile")


def state_dir(value):
    path = Path(value).expanduser()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    parser.add_argument("--state-dir", default=DEFAULT_STATE_DIR, help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)
    p_set = sub.add_parser("set", help="сохранить URL (и опционально API-токен, пользователя)")
    p_set.add_argument("--url", required=True)
    p_set.add_argument("--token", default="")
    p_set.add_argument("--user", default="")
    sub.add_parser("show", help="показать конфиг (токен маскируется)")
    sub.add_parser("clear", help="удалить сохранённый конфиг")
    p_test = sub.add_parser("test", help="проверить связь (претаски и cracker binary)")
    p_test.add_argument("--password", default="", help="разовый вход вместо сохранённого токена")
    args = parser.parse_args()
    directory = state_dir(args.state_dir)
    if args.command == "set":
        url = args.url.strip().rstrip("/")
        if not url.lower().startswith(("http://", "https://")):
            sys.exit("ошибка: URL должен начинаться с http:// или https://")
        hashtopolis.save_config(directory, url=url, token=args.token.strip(), user=args.user.strip())
        print("Конфиг сохранён: " + directory + "/htp.json (0600)")
        return
    if args.command == "clear":
        hashtopolis.clear_config(directory)
        print("Конфиг удалён.")
        return
    cfg = hashtopolis.load_config(directory)
    if args.command == "show":
        if not cfg:
            print("Конфиг не задан. wifit3-mobile-htp set --url https://… [--token …] [--user …]")
            return
        print("url:   " + cfg.get("url", ""))
        print("user:  " + cfg.get("user", ""))
        print("token: " + ("сохранён (" + str(len(cfg["token"])) + " символов)" if cfg.get("token") else "нет"))
        return
    # test
    if not cfg.get("url"):
        sys.exit("ошибка: конфиг не задан — сначала set --url …")
    client = hashtopolis.HashtopolisClient(cfg["url"], token=cfg.get("token", ""),
                                           user=cfg.get("user", ""), password=args.password)
    try:
        info = client.verify()
        binary_id, version = client.newest_binary()
    except hashtopolis.HashtopolisError as exc:
        sys.exit(f"ошибка: {exc}")
    print(f"Связь есть: {cfg['url']} · pretask'ов: {info['pretasks']} · hashcat {version} (binary {binary_id})")


if __name__ == "__main__":
    main()
