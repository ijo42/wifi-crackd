#!/data/data/com.termux/files/usr/bin/bash
# Explicit opt-in. Does NOT grant RUN_COMMAND to Android apps; user still grants per app.
set -euo pipefail
if [ -z "${TERMUX_VERSION:-}" ] && [[ "${PREFIX:-}" != *com.termux* ]]; then
 echo 'Этот скрипт предназначен только для Termux.' >&2; exit 1
fi
printf 'Это разрешает внешним приложениям с выданным RUN_COMMAND запускать команды в Termux.\nВыдавайте RUN_COMMAND только доверенным приложениям.\nПродолжить? Введите YES: '
read -r answer
[ "$answer" = YES ] || { echo 'Настройка не изменена.'; exit 0; }
python - <<'PY'
from pathlib import Path
import re, shutil
path=Path.home()/'.termux/termux.properties'
path.parent.mkdir(parents=True,exist_ok=True)
text=path.read_text() if path.exists() else ''
if path.exists():
 backup=path.with_name('termux.properties.before-wifit3-mobile')
 if not backup.exists(): shutil.copy2(path,backup)
# Replace only the relevant property, preserve unrelated settings/comments.
lines=[line for line in text.splitlines() if not re.match(r'^\s*allow-external-apps\s*=',line)]
lines.extend(['','allow-external-apps = true'])
path.write_text('\n'.join(lines)+'\n')
print('allow-external-apps = true; резервная копия исходных настроек сохранена, если файл существовал.')
PY
termux-reload-settings
printf '\nТеперь в Wifit3 Mobile нажмите запуск и выдайте разрешение RUN_COMMAND.\nДля отключения: allow-external-apps = false в ~/.termux/termux.properties, затем termux-reload-settings.\n'
