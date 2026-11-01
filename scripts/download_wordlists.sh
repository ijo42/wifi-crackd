#!/usr/bin/env bash
# Скачивание вордлистов в ./wordlists (монтируется в контейнер read-only).
# Использование:
#   ./scripts/download_wordlists.sh            # rockyou + top1k
#   ./scripts/download_wordlists.sh --big      # + insomnia (большие словари, качается долго)
set -euo pipefail

cd "$(dirname "$0")/.."
DEST=wordlists
mkdir -p "$DEST"

fetch() { # url out
    if [ -f "$2" ]; then echo "уже есть: $2"; return; fi
    echo "качаю $2 ..."
    curl -fL --retry 3 -o "$2.part" "$1"
    mv "$2.part" "$2"
}

# rockyou — классика (14.5 млн строк, gz)
fetch "https://gitlab.com/kalilinux/packages/wordlists/-/raw/kali/master/rockyou.txt.gz" \
      "$DEST/rockyou.txt.gz"
if [ -f "$DEST/rockyou.txt.gz" ] && [ ! -f "$DEST/rockyou.txt" ]; then
    echo "распаковка rockyou.txt.gz ..."
    gunzip -kf "$DEST/rockyou.txt.gz"
fi

# top1k — короткий словарь с best64 на первом словарном этапе
fetch "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/Pwdb_top-1000.txt" \
      "$DEST/top1k.txt"

if [ "${1:-}" = "--big" ]; then
    # insomnia (~3.5 ГБ) — источник weakpass.com, ссылка может меняться
    fetch "https://weakpass.com/download/90/insomnia.txt" "$DEST/insomnia.txt" || \
        echo "не удалось скачать insomnia — возьми руками с https://weakpass.com/wordlist/90"
fi

echo "готово: $(ls -lh "$DEST" | tail -n +2)"
