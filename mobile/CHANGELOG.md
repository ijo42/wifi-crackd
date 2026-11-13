# Changelog

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
