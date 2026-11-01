# wifi-crackd

Серверный GPU-брут WPA/WPA2-хендшейков и PMKID (hashcat `-m 22000`, CUDA) + лёгкий веб-интерфейс.
Конечное устройство (ноутбук/малина с USB-Wi-Fi адаптером) ловит захваты **wifit3** или **wifite3**,
клиентский скрипт `wifisend.py` отправляет их на сервер, сервер брутит по стадиям: сперва базовые
комбинации (маски), затем вордлисты.

> ⚠️ **Только для авторизованного аудита** — используй на своих сетях или с письменного разрешения
> владельца. Доступ к чужим сетям незаконен.

## Архитектура

```
[ конечное устройство ]                [ сервер с GPU ]
wifit3 / wifite3  →  wifisend.py  ──►  FastAPI (api/admin)
  captures/*.hc22000    (uv-скрипт)      ├─ ingest: unzip + hcxpcapngtool + валидация 22000
  *.pcap *.pmkid                         ├─ SQLite очередь задач
                                         ├─ воркер: hashcat -m 22000 (стадии из config.yaml)
                                         └─ веб: загрузка / админка / токены
```

Поток задач:

- **Анонимная загрузка** (без токена) → состояние `pending`, ждёт **акцепта админа** в вебе.
- **Загрузка с токеном** (`Authorization: Bearer wfk_…`) → сразу `queued`.
- Воркер гоняет стадии из `config.yaml` по порядку; potfile общий — уже взломанные хэши не брутятся заново.
- Найденные пароли **только в админке** (`/admin/jobs/{id}`); публичный статус (`/api/jobs/{id}?secret=`)
  отдаёт лишь состояние/прогресс/ETA.

## Запуск сервера

Требования: Docker + nvidia-container-toolkit (GPU должен быть виден из контейнера).

```bash
# 1. конфиг
cp config.example.yaml config.yaml        # стадии брута и лимиты
cp .env.example .env                      # ADMIN_PASSWORD, SECRET_KEY (openssl rand -hex 32)

# 2. вордлисты
./scripts/download_wordlists.sh           # rockyou + top1k (опц. --big)

# 3. запуск
docker compose up -d --build

# 4. проверить GPU в контейнере
docker compose exec crackd hashcat -I     # секция "CUDA Info" + твоя карта
docker compose exec crackd hashcat -b -m 22000   # бенчмарк
```

Проверка без GPU: в `.env` поставь `DRY_RUN=1` — воркер имитирует брут и пишет демо-пароли
(в potfile попадает `dry-run-demo`); весь пайплайн проверяется end-to-end.

Веб: `http://сервер:8080/` — загрузка (drag&drop), `/admin` — админка (пароль из `ADMIN_PASSWORD`).

### Нюанс WSL2 / CUDA

hashcat грузит `libcuda.so` и `libnvrtc.so.1` по именам без версии. В WSL-контейнере:
- `libcuda` живёт в драйверном сторe (`/usr/lib/wsl/drivers/…`) без dev-симлинка;
- `libnvrtc` из apt ставится как `libnvrtc.so.12` (hashcat ищет `.so.1`).

Это чинит `server/fix-gpu.sh`, который entrypoint запускает на старте (ставит симлинки под root
и роняет привилегии до непривилегированного пользователя). В compose уже выставлены
`NVIDIA_VISIBLE_DEVICES=all` и `NVIDIA_DRIVER_CAPABILITIES=all` — без них тулкит вообще
не монтирует драйвер в контейнер. Если `hashcat -I` не видит карту — проверь, что установлен
nvidia-container-toolkit (`sudo apt install nvidia-container-toolkit && sudo nvidia-ctk runtime
configure --runtime=docker && sudo systemctl restart docker`).

## Клиент (конечное устройство)

Установка как тулзы (uv ставит зависимости сам, команда `wifisend` доступна глобально):

```bash
uv tool install "wifisend @ git+https://github.com/<you>/wifi-crackd.git#subdirectory=client"
```

Или разовый запуск без установки:

```bash
uv run client/wifisend.py ~/wifit3/captures --url http://сервер:8080
```

```bash
# без токена: задача уйдёт на подтверждение админу
wifisend ~/wifit3/captures --url http://сервер:8080

# с токеном: сразу в очередь брута
wifisend ~/wifit3/captures --url http://сервер:8080 --token wfk_... --wait
```

Переменные окружения `CRACKD_URL` / `CRACKD_TOKEN` задают дефолты для `--url` / `--token`.

Скрипт рекурсивно берёт `*.hc22000 *.22000 *.pmkid *.16800 *.pcap *.cap *.pcapng *.hccapx`
и **пропускает служебное**: `*.meta`, `jobs.json`, `jobs/`, `*_wpa_psk.txt`, `*_wps_*.txt`,
`*_wep_key.txt`, `*.log`, `*.potfile`, `wifit3_captures_*.zip`, `pwnd/`, `*.cracked`.

## API

| Метод | Путь | Описание |
|---|---|---|
| POST | `/api/upload` | multipart `captures` (zip), `note`; `Authorization: Bearer wfk_…` опционален. Возвращает `{job_id, secret, …}` |
| GET | `/api/jobs/{id}?secret=…` | статус: state/stage/progress/speed/eta — без паролей |
| GET/POST | `/login`, `/logout` | вход админа (cookie-сессия) |
| POST | `/admin/jobs/{id}/accept·reject·stop·retry·delete` | управление задачами |
| GET/POST | `/admin/tokens` | создание/отзыв токенов (ключ показывается один раз) |

## Формат 22000

Сервер валидирует строки по правилам wifit3 (`WPA*01/02` — 9 полей, `WPA*03/04` (FT) — 12;
hex в нижний регистр, ESSID — hex utf-8). Конвертации на приёмке: `.pmkid`/`.16800` → `WPA*01`,
`.hccapx` → `WPA*02`, `pcap/cap/pcapng` — через `hcxpcapngtool`. FT-строки (802.11r) hashcat
`-m 22000` не брутит — они считаются (`ft_count`) и пропускаются.

## Стадии брута (`config.yaml`)

Каждая стадия — сырые аргументы hashcat. Дефолт: 8 цифр → RU-телефоны (9…, 89…, 79…) →
top1k + best64 → rockyou + dive. Правь под себя; `/wordlists` монтируется read-only.

## Разработка

```bash
uv venv .venv && uv pip install -p .venv/bin/python -r server/requirements.txt pytest httpx
.venv/bin/python -m pytest tests/ -q       # 23 теста, без GPU (DRY_RUN)
```

Локальный сервер без Docker:

```bash
cd server && DRY_RUN=1 SECRET_KEY=... ADMIN_PASSWORD=... \
  CRACKD_DATA=/tmp/crackd CRACKD_CONFIG=../config.yaml ../.venv/bin/uvicorn app.main:app --port 8080
```

## Структура

```
wifi-crackd/
├── docker-compose.yml / .env.example / config(.example).yaml
├── server/{Dockerfile,requirements.txt}
│   └── app/           main, config, db, security, ingest, hashcat, worker, api, admin, cleanup
│       ├── templates/ upload, login, dashboard, job, tokens, config (RU)
│       └── static/app.css
├── client/                       # пакет wifisend (uv tool install / uv run)
│   ├── pyproject.toml
│   ├── README.md
│   └── wifisend.py               # тот же файл работает и как PEP 723 скрипт
├── scripts/download_wordlists.sh
├── wordlists/  data/             # volumes (data: sqlite, uploads, potfile)
└── tests/                        # pytest + фикстуры wifit3/wifite3
```
