# wifi-crackd

Набор инструментов WiFi-аудита вокруг [Hashtopolis](https://github.com/hashtopolis/server):
полевое Android/Termux-устройство (`mobile/`) и клиент для конечных боксов (`client/wifisend`).
Брут WPA/WPA2-хендшейков и PMKID (`hashcat -m 22000`) выполняет **внешний сервер Hashtopolis** —
собственного GPU-движка в репозитории больше нет.

> ⚠️ **Только для авторизованного аудита** — используй на своих сетях или с письменного разрешения
> владельца. Доступ к чужим сетям незаконен. Deauth — активная атака: она отключает клиентов.

## Архитектура

```
[ телефон + USB Wi-Fi ]                    [ сервер Hashtopolis (твой) ]
mobile/wifit3-mobile (Termux)              ├─ hashlist PLAIN / hashTypeId 22000
  ├─ пассивный обзор (wifit3 upstream)     ├─ pretask-цепочки: словари → правила → маски
  ├─ авторизованный deauth → хендшейк      └─ GPU-агенты брутят
  ├─ сбор hc22000 (сериализаторы wifit3)         ▲            ▲
  └─ отправка хешей батчами ─────────────────────┘            │
[ ноутбук / малина с USB Wi-Fi ]                              │
client/wifisend.py (uv tool) ── захваты wifit3/wifite3 ───────┘
```

- **[mobile/](mobile/README.md)** — APK + локальный Python-модуль в Termux: пассивный обзор,
  целевой deauth (upstream `DeauthCampaign`, PMF → CSA), сбор крэкабельных hc22000 и загрузка
  в Hashtopolis (hashlist + цепочка задач из pretask'ов), dry-run, приватный конфиг 0600.
- **[client/](client/README.md)** — `wifisend`: собирает захваты из папки (включая конвертацию
  pcap через `hcxpcapngtool`), режет на батчи по 250 строк, создаёт hashlist'ы и задачи.

## Быстрый старт (телефон)

```bash
# 1. Termux: установка как глобальная тулза с USB-драйвером (основной способ)
uv tool install 'wifit3-mobile[usb] @ git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile'
# (альтернатива без uv: bash mobile/tools/install-termux.sh)

# 2. Hashtopolis: адрес/токен — один раз
wifit3-mobile-htp set --url https://htp.example.com --token <API-токен>

# 3. Запуск: APK («Запустить USB-режим в Termux») или вручную
wifit3-mobile            # код подключения печатается в терминале
wifit3-mobile --demo     # диагностика без USB, синтетические данные, отправка заблокирована
```

Останов без Ctrl+C: кнопка «Завершить модуль» во вкладке «Модуль» веб-интерфейса, «Стоп модуль» в APK или `wifit3-mobile-service stop`.

В интерфейсе: «Адаптер» → разрешение на аудит → сканирование; детали сети → **Deauth** для
нового хендшейка; вкладка **«Хеши»** → экспорт hc22000 или отправка на Hashtopolis.

## Настройка Hashtopolis

Цепочка атак по умолчанию подбирается по подстрокам имён pretask'ов сервера
(`dict router-defaults`, `rule OneRule x router-defaults`, `dict ru-phone-round`,
`mask 8 digits`, `mask RU mobile 8-9xx`) — см. `--pretask` / `--all-wpa-pretasks` /
вкладку «Хеши». Нужен залитый hashcat-бинарник (Cracker binaries). Нюансы Hashtopolis
(приоритет 1, keyspace-расчёт, PLAIN vs WPA-формат) описаны в [client/README.md](client/README.md).

## Разработка

```bash
# mobile: тесты (DEMO-режим, без радио и upstream)
cd mobile && python -m venv .venv && . .venv/bin/activate
python -m pip install ".[dev]" && python -m pytest -q
# полный набор с upstream ([usb]) — на Linux/Termux; см. mobile/README.md

# client: разовый запуск без установки
uv run client/wifisend.py --help
```

Структура:

```
wifi-crackd/
├── mobile/                  # APK + Termux-модуль wifit3-mobile (см. mobile/README.md)
│   ├── bridge/wifit3_mobile/   # engine, attacks, hashes, hashtopolis, server, service, UI
│   ├── android/                   # WebView-обёртка + RUN_COMMAND lifecycle
│   ├── tools/                     # install-termux.sh, enable-termux-link.sh, build-apk.sh
│   └── tests/
├── client/wifisend.py       # отправка захватов → Hashtopolis (uv tool / PEP 723)
└── .github/workflows/       # CI: python-тесты + uvx, сборка APK, smoke wifisend
```

История: до 0.4 репозиторий содержал собственный FastAPI+hashcat сервер; он удалён —
приём/валидацию/веб-админку заменила прямая отправка в Hashtopolis из `mobile` и `wifisend`.
