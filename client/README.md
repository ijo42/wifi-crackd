# wifisend

Клиент [Hashtopolis](https://github.com/hashtopolis/server): собирает WiFi-хендшейки/
PMKID из папки захватов (wifit3 / wifite3 или готовые hc22000), конвертирует их в
hashcat-формат и **засылает пачками**: один hashlist на батч + цепочка атак из
готовых pretask'ов сервера.

## Установка (uv tool)

```bash
uv tool install "wifisend @ git+https://github.com/ijo42/wifi-crackd.git#subdirectory=client"
```

## Запуск без установки (uv run)

```bash
uv run wifisend.py <папка с захватами> --url https://hashtopolis.example.com --user admin
```

## Что делает

1. Собирает из папки: текстовые `*.hc22000 *.22000 *.pmkid *.16800` — напрямую;
   `*.pcap *.cap *.pcapng *.hccapx` — через внешний `hcxpcapngtool` (флаг `--hcxtool`).
   Служебные файлы wifit3/wifite3 (`*.meta`, `jobs.json`, `*_wpa_psk.txt`, …) пропускаются.
2. Дедуплицирует hc22000-строки, режет на **батчи** по `--batch N` строк (по умолчанию 250).
3. Для каждого батча: `POST /api/v2/ui/hashlists` (format=0 PLAIN, hashTypeId=22000,
   sourceData=base64) + клон выбранных **pretask'ов** в задачи на этот hashlist.
4. `--wait` поллит `cracked/hashCount` по всем батчам до полного крэка или таймаута.

## Цепочка атак

По умолчанию клиент авто-подбирает pretask'и сервера по подстрокам имени
(эскалация: словарь дефолтов → OneRule → словарь РФ-телефонов → маска 8 цифр →
маска RU-мобильных). Посмотреть, что есть на сервере:

```bash
wifisend --url https://… --user admin --list-pretasks
```

Задать явно:

```bash
wifisend ./captures --url … --pretask 1 --pretask 12 --pretask 4     # свои id
wifisend ./captures --url … --all-wpa-pretasks                       # вообще все WPA2 | *
```

Pretask'и создаются скриптами `04-wifi.sh` / `05-rules.sh` из репо
[hashtopolis-cuda](https://github.com/…); можно завести свои в Web UI → Pretasks.

## Примеры

```bash
# dry-run: показать план (батчи, цепочку), ничего не отправляя
wifisend ./captures --url http://10.0.0.5:8081 --user admin --password … --dry-run

# отправить пачками по 100 хешей и дождаться результата (лимит 1 час)
wifisend ./captures --url http://10.0.0.5:8081 --user admin --password … \
    --batch 100 --wait --timeout 3600

# с готовым API-токеном (Users → API tokens в UI Hashtopolis)
wifisend ./captures --url https://htp.example.com --token eyJ0eXAi… --wait
```

Переменные окружения: `HTP_URL`, `HTP_TOKEN` / `HTP_USER`, `HTP_PASSWORD`.

## Важные нюансы Hashtopolis

- **Задачи с `priority=0` невидимы для агентов** (в `getBestTask` обычный путь
  отсекает нулевой приоритет) — клиент всегда ставит `priority=1`. Если создаёшь
  задачи руками через API — не забывай про это.
- После создания задач сервер считает keyspace каждой задачи (по очереди,
  ~1 задача/мин) — пауза перед стартом брута на больших батчах нормальна.
- Формат WPA (format=1) сервер ломает — клиент шлёт PLAIN + hashTypeId=22000.

## Конфиг: url/token сохраняются

После первого успешного запроса клиент пишет конфиг в
`~/.config/wifisend/config.json` (переопределяется env `WIFISEND_CONFIG`;
`--no-save` отключает запись):

- сохраняются всегда `url` и `user`;
- `token` сохраняется, только если ты входил через `--token` (API-токен
  долгоживущий). JWT от логина `--user/--password` **не сохраняется** — он
  короткоживущий, пароль на диск не пишется.

Последующие запуски — вообще без аргументов:

```bash
wifisend ./captures --dry-run
wifisend ./captures --wait
```

## Формат хешей

Hashtopolis принимает hc22000-star-строки (`WPA*01*<pmkid>*<ap>*<sta>*<essid-hex>***`)
в **PLAIN-хешлисте с hashTypeId=22000**. Формат WPA (format=1) сервер ломает
(legacy-колоночный) — клиент всегда шлёт plain. Конвертация реальных захватов:

```bash
hcxpcapngtool -o dump.hc22000 capture.pcapng
```

Только для сетей, владеть/аудит которых ты имеешь право.
