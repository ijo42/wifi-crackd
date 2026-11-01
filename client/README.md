# wifisend

Клиент сервера [wifi-crackd](../README.md): собирает захваты wifit3 / wifite3 из папки
и отправляет на сервер брута.

## Установка (uv tool)

```bash
uv tool install "wifisend @ git+https://github.com/<you>/wifi-crackd.git#subdirectory=client"
```

## Запуск без установки (uv run)

```bash
uv run wifisend.py <папка с захватами> --url http://сервер:8080
```

Оба варианта — одна и та же программа; uv сам ставит зависимости (httpx).

## Использование

```bash
wifisend ~/wifit3/captures --url http://сервер:8080          # анонимно → акцепт админа
wifisend ~/wifit3/captures --url http://сервер:8080 --token wfk_... --wait   # сразу в очередь
```

Переменные окружения: `CRACKD_URL`, `CRACKD_TOKEN` — значения по умолчанию для --url/--token.
