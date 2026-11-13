# Публикация: репозиторий ijo42/wifi-crackd

Проект живёт сабдиректорией `mobile/` в репозитории [ijo42/wifi-crackd](https://github.com/ijo42/wifi-crackd).
Пакет `wifit3-mobile` 0.4.0 даёт три команды: `wifit3-mobile`, `wifit3-mobile-service`, `wifit3-mobile-htp`.
wheel содержит статический UI; базовый пакет без runtime-зависимостей; extra `[usb]` загружает закреплённый upstream Git commit.

`bin/`, `dist/`, APK, private keys/keystores, service.json/log, локальные коды и результаты тестов исключены `.gitignore`. Сама публикация имени/логотипа должна оставаться ясно неофициальной: это companion, не официальный релиз upstream.

## Запуск через uvx (основной сценарий)

Нужен Git на машине с uvx; для живого USB добавьте extra `[usb]`:

```bash
uvx --from 'git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile' wifit3-mobile --demo
uvx --from 'wifit3-mobile[usb] @ git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile' wifit3-mobile
uvx --from 'git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile' wifit3-mobile-service start --demo
uvx --from 'git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile' wifit3-mobile-service stop
uvx --from 'git+https://github.com/ijo42/wifi-crackd.git#subdirectory=mobile' wifit3-mobile-htp set --url https://htp.example
```

Предпочитать закреплённый commit вместо плавающей main:

```bash
uvx --from 'git+https://github.com/ijo42/wifi-crackd.git@COMMIT#subdirectory=mobile' wifit3-mobile --demo
```

Из локального дерева: `uvx --from mobile wifit3-mobile --demo`; из wheel — `uvx --from ./dist/wifit3_mobile-0.4.0-py3-none-any.whl wifit3-mobile --demo`.
Проверено: `uvx --from 'git+file://…/wifi-crackd#subdirectory=mobile'` собирает пакет и возвращает 0.4.0 для всех трёх команд (Windows; Linux-путь гоняет CI).

## Сборка и проверки

```bash
python -m pip install '.[dev]'
python -m pytest -q
python -m build
python -m twine check dist/*
```

Интеграционные тесты настоящего upstream требуют `pip install '.[usb]'` и свободный локальный порт 8765. Тесты не используют радио. Поддержку uv на конкретном телефоне нужно проверить отдельно; обычный Termux-установщик сохранён.

## PyPI — отдельно

PyPI-публикация не запрошена/не выполнялась. Наличие имени в pyproject не резервирует его в индексе. Extra `[usb]` содержит VCS direct URL; PyPI не принимает такие зависимости при загрузке дистрибутивов. Для отдельной будущей публикации в индекс потребуется изменить схему зависимости/установки. `twine check` валидирует описание/метаданные, но не означает, что пакет загружен или будет принят индексом.

## Сборка и проверки

```bash
python -m pip install '.[dev]'
python -m pytest -q
python -m build
python -m twine check dist/*
```

Интеграционные тесты настоящего upstream требуют `pip install '.[usb]'` и свободный локальный порт 8765. Тесты не используют радио. Установка Git-extra была проверена на Linux. Поддержку uv на конкретном телефоне нужно проверить отдельно; обычный Termux-установщик сохранён.

## PyPI — отдельно

PyPI-публикация не запрошена/не выполнялась. Наличие имени в pyproject не резервирует его в индексе. Extra `[usb]` содержит VCS direct URL; PyPI не принимает такие зависимости при загрузке дистрибутивов. Для отдельной будущей публикации в индекс потребуется изменить схему зависимости/установки и согласовать имя/доступ. `twine check` валидирует описание/метаданные, но не означает, что пакет загружен или будет принят индексом.
