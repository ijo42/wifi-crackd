# Changelog

## 0.4.2

- **Активные кампании PMKID и WPS** (апстримные `PmkidHarvestAttack` и `WpsCampaign`): единая карточка кампаний в фокусе цели — гейтинг по классам апстрима (`visible`/`ineligible_reason`: скрытый SSID, WPS locked, PSK/RSN), один слот кампании за сессию, автостоп по `check_auto_stop` (WPS), фиксация канала цели и восстановление перебора для всех кампаний. PMKID попадает в `ap.handshakes` через парсер M1 → hc22000 (`WPA*01`) подхватывается автоматически; WPS показывает найденные PIN/PSK в карточке и журнале. DEMO-шимы для всех трёх кампаний.
- API: `POST /api/attack/start {campaign, bssid, authorized}` и `/api/attack/stop` ( `/api/deauth/*` остались как легаси-алиасы); state: `attack` (`deauth` — алиас).
- Фильтры списка сетей: тип защиты (WPA2/WPA3/SCE/OPEN/WEP), «без хешей»/«с хешами», «есть клиенты»/«без клиентов»; сортировка по числу клиентов. `serialize_ap` отдаёт `hidden`/`rsn_valid` для гейтинга на клиенте.
- Body limit поднят до 16384 байт: долгоживущий API-токен Hashtopolis не влезал в 4096.
- Документация: основной способ установки — `uv tool install 'wifit3-mobile[usb] @ git+…#subdirectory=mobile'`; Termux-скрипт — альтернатива.
- APK 0.4.2 (versionCode 6).

## 0.4.1

- **Исправлен главный дефект deauth:** кампания теперь, как в апстримном Focus‑экране, останавливает перебор каналов и фиксирует пул на канале цели (`stop_hopping` + `set_channel`), а после завершения (авто‑захват или ручной стоп) восстанавливает перебор. Раньше hop‑цикл уносил карточку с канала цели — EAPOL‑обмен приходил вне канала, хендшейки не записывались (симптом: «deauth в журнале есть, хешей нет»). Итог кампании — в `state.deauth.last`.
- Веб‑интерфейс переработан по мотивам апстримного TUI: фокус цели с живой карточкой кампании (acks/broadcast/CSA, статус захвата, итог последней попытки), маяки/клиенты/PMF/SCE в списке сетей, хеши конкретной сети в фокусе, вкладка «Модуль» вместо «Адаптер». Исправлен JS‑краш `Cannot read properties of null (reading 'psk_family')`.
- **Остановка модуля без Ctrl+C:** `/api/shutdown` работает и в ручном режиме; в интерфейсе кнопка «Завершить модуль» (двухшаговое подтверждение без нативных диалогов — они не работают в WebView без WebChromeClient).
- Живой USB‑режим из Termux объявлен основным сценарием: панель APK, заголовки UI и документация; «Демо» помечен как диагностика. APK 0.4.1 (versionCode 5).
- check‑ui расширен: кампания deauth в DEMO, вкладка хешей, dry‑run/блокировка отправки, graceful shutdown (сервер действительно завершается).

## 0.4.0

- Репозиторий проекта перенесён в [wifi-crackd](../README.md) как `mobile/`; собственный GPU-движок кряка из wifi-crackd удалён — брут выполняет внешний Hashtopolis.
- **Активный deauth (авторизованный аудит):** `POST /api/deauth/start|stop`, обёртка над upstream `DeauthCampaign` (двусторонние deauth-пары по клиентам + broadcast; для PMF — только CSA-маяки; автоматическая остановка при новом крэкабельном захвате). Только для подтверждённых WPA/WPA2-PSK целей; требует явного согласия.
- **Сбор хешей hc22000:** из живого sink через собственные сериализаторы upstream (`eapol_hashlines`/`pmkid_hashline`); скрытый SSID хеш не даёт. Счётчики в state, строки через `GET /api/hashes`, текстовый экспорт (Android `saveHashes` или скачивание в браузере).
- **Отправка в Hashtopolis:** stdlib-клиент (без новых зависимостей) — hashlist PLAIN/22000 батчами + цепочка задач из pretask'ов сервера (авто-подбор по эскалационной цепочке, явные id или все «WPA2 | »), dry-run, проверка связи. Конфиг (url/user/долгоживущий API-токен) — приватный файл 0600; пароль и JWT не сохраняются. В DEMO реальная отправка заблокирована.
- UI: вкладка «Хеши» с формой Hashtopolis, бейдж активного deauth, кнопка deauth в деталях сети, счётчик хешей в метриках.
- Новый CLI `wifit3-mobile-htp` (set/show/clear/test) + wrapper в установщике; установщик опционально ставит `hcxtools` (офлайн-конвертация pcap для wifisend).
- APK 0.4.0 (versionCode 4): bridge `saveHashes` для экспорта hc22000, обновлённые подсказки.

## 0.3.0

- Standard root pyproject, wheel/sdist and CLI entrypoints suitable for uvx.
- Optional pinned USB backend; base demo/control package has no runtime dependencies.
- `--version` for both commands.
- Passive RX deauth/disassociation counters and bounded 150-event ring in UI/API/JSON export. Protected bodies do not expose an inferred plaintext reason. No TX/attack functionality.
- Publication-ready documentation, security boundaries and CI build/uvx checks. No repository or PyPI publication performed.
- Termux installer uses root package and preserves full-upgrade/HTTPS preflight repair.

## 0.2.0

- Termux RUN_COMMAND lifecycle integration and automatic local pairing.
- Idempotent start/status/stop controller and loopback security.
- Installer recovery for partial Termux upgrades.

## 0.1.0

- Android companion, passive USB survey, local responsive UI and explicit demo mode.
