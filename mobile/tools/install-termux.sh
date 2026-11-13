#!/data/data/com.termux/files/usr/bin/bash
# Termux is rolling-release: synchronize ALL packages before installing dependencies.
# No sshd/ssh-agent changes, TLS bypasses, arbitrary .deb downloads, or data deletion.
set -euo pipefail
if [ -z "${TERMUX_VERSION:-}" ] && [[ "${PREFIX:-}" != *com.termux* ]]; then
 echo 'Этот установщик предназначен только для Termux.' >&2; exit 1
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$HOME/.local/share/wifit3-mobile"
COMMIT=04a4e2b6e3d6d54b7befd526bdb7232694ec49ea
REPOSITORY=https://github.com/OliverRhyme/wifit3-termux.git

network_check() {
 if ! curl --version; then
  printf '\nНе запускается curl: вероятна несовместимость libcurl и её зависимостей.\nСначала: apt update && apt full-upgrade\nЕсли после успешного обновления ошибка осталась:\napt install --reinstall curl libcurl libngtcp2 git\nНикакие библиотеки вручную не копируйте; TLS не отключайте.\n' >&2
  return 1
 fi
 # git --version alone does not load git-remote-https/libcurl. This checks the real helper.
 if ! git ls-remote --exit-code "$REPOSITORY" HEAD >/dev/null; then
  printf '\nGit HTTPS не прошёл проверку. Если CANNOT LINK EXECUTABLE остался, восстановите пакеты через apt.\nЕсли это ошибка сети/TLS, проверьте сеть/дату/репозиторий; не отключайте проверку сертификатов.\n' >&2
  return 1
 fi
}

if [ "${1:-}" = --check ]; then
 printf 'Диагностика без установки/изменения настроек:\n'
 dpkg-query -W curl libcurl libngtcp2 git || true
 printf '\nУдерживаемые пакеты (ничего автоматически не снимается):\n'
 apt-mark showhold || true
 network_check
 printf '\nПроверка curl и Git HTTPS пройдена. Это не проверка Android/USB.\n'
 exit 0
fi
if [ "$#" -ne 0 ]; then echo 'Использование: bash tools/install-termux.sh [--check]' >&2; exit 2; fi

printf 'Перед установкой нужно обновить ВСЕ пакеты Termux через apt, чтобы не смешивать версии библиотек.\nБудут выполнены apt update, apt full-upgrade и установка зависимостей.\nКоманды покажут план и запросят подтверждение; если предлагается неожиданное удаление — отмените.\nSSH не включается, пользовательские файлы не удаляются. Остановите работающий модуль перед обновлением.\nПродолжить? Введите YES: '
read -r answer
[ "$answer" = YES ] || { echo 'Установка отменена, пакеты не изменены.'; exit 0; }
# Do not use pkg here: its mirror checks can depend on the broken curl.
apt update
apt full-upgrade
apt install python libusb termux-api git curl ca-certificates
network_check

mkdir -p "$DATA"
if [ -e "$DATA/upstream" ] && [ ! -d "$DATA/upstream/.git" ]; then
 printf 'Каталог %s/upstream существует, но это не Git checkout. Ничего не удалено.\nПереместите его в резервную папку с новым именем и повторите установку; см. INSTALL-REPAIR.md.\n' "$DATA" >&2
 exit 1
fi
if [ ! -d "$DATA/upstream/.git" ]; then
 # Stage a fresh clone separately: a failed download never becomes the working checkout.
 DOWNLOAD="$(mktemp -d "$DATA/upstream-download.XXXXXXXX")"
 if ! git clone --filter=blob:none --no-checkout "$REPOSITORY" "$DOWNLOAD"; then
  printf 'Клонирование не завершено. Временный каталог сохранён: %s\nИсправьте ошибку выше и повторите. Рабочий checkout не заменялся.\n' "$DOWNLOAD" >&2
  exit 1
 fi
 git -C "$DOWNLOAD" fetch --depth 1 origin "$COMMIT"
 git -C "$DOWNLOAD" checkout --detach "$COMMIT"
 if [ -e "$DATA/upstream" ]; then echo 'Каталог upstream появился во время загрузки; ничего не заменено.' >&2; exit 1; fi
 mv "$DOWNLOAD" "$DATA/upstream"
fi
if [ "$(git -C "$DATA/upstream" remote get-url origin)" != "$REPOSITORY" ]; then
 echo 'Неожиданный репозиторий в каталоге установки; остановка.' >&2; exit 1
fi
git -C "$DATA/upstream" fetch --depth 1 origin "$COMMIT"
git -C "$DATA/upstream" checkout --detach "$COMMIT"
python -m venv "$DATA/runtime"
"$DATA/runtime/bin/python" -m pip install "$DATA/upstream" "$ROOT"
# hcxtools: офлайн-конвертация *.pcap в hc22000 (для wifisend); не обязателен для работы модуля.
apt install hcxtools || printf 'hcxtools не установлен: конвертация pcap будет недоступна (hc22000 мобильный собирает сам).\n' >&2
mkdir -p "$PREFIX/bin"
printf '#!/data/data/com.termux/files/usr/bin/bash\nexec "%s/runtime/bin/wifit3-mobile" "$@"\n' "$DATA" > "$PREFIX/bin/wifit3-mobile"
printf '#!/data/data/com.termux/files/usr/bin/bash\nexec "%s/runtime/bin/wifit3-mobile-service" "$@"\n' "$DATA" > "$PREFIX/bin/wifit3-mobile-service"
printf '#!/data/data/com.termux/files/usr/bin/bash\nexec "%s/runtime/bin/wifit3-mobile-htp" "$@"\n' "$DATA" > "$PREFIX/bin/wifit3-mobile-htp"
chmod +x "$PREFIX/bin/wifit3-mobile" "$PREFIX/bin/wifit3-mobile-service" "$PREFIX/bin/wifit3-mobile-htp"
printf '\nУстановлено. Также установите приложение Termux:API из того же источника, что и Termux.\nЗапуск: wifit3-mobile\nДемо: wifit3-mobile --demo\n'
printf '\nHashtopolis (хеши уходит брутить туда): wifit3-mobile-htp set --url https://… [--token …]\n'
printf '\nДля запуска из APK (необязательно, отдельное согласие): bash tools/enable-termux-link.sh\nПроверка: wifit3-mobile-service status\n'
