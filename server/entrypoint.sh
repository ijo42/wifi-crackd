#!/bin/bash
# entrypoint: fix-gpu.sh + права на /data + drop privileges → uvicorn.
set -e

/fix-gpu.sh

mkdir -p /data
chown -R crackd:crackd /data 2>/dev/null || true

# hashcat v8 пишет hashcat.pid / hashcat.outfiles рядом с бинарём
chown -R crackd:crackd /opt/hashcat 2>/dev/null || true

exec setpriv --reuid=crackd --regid=crackd --init-groups \
    /opt/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8080
