#!/bin/bash
# Починка GPU-стека для hashcat (вызывается из entrypoint; можно звать руками).
#
# hashcat делает dlopen("libcuda.so") и dlopen("libnvrtc.so.1"):
#  - libnvrtc из apt ставится как libnvrtc.so.12 (без .1)
#  - libcuda в WSL живёт в драйверном сторe (/usr/lib/wsl/drivers/…) без dev-симлинка
set -e

# первичный ldconfig: nvidia-тулкит мог только что смонтировать драйверные пути
ldconfig 2>/dev/null || true

if [ -e /usr/lib/x86_64-linux-gnu/libnvrtc.so.12 ]; then
    ln -sf /usr/lib/x86_64-linux-gnu/libnvrtc.so.12 /usr/lib/x86_64-linux-gnu/libnvrtc.so.1
fi

CUDA_1="$(ldconfig -p 2>/dev/null | awk '/libcuda\.so\.1/{print $NF; exit}')"
if [ -n "${CUDA_1}" ]; then
    ln -sf "${CUDA_1}" /usr/lib/wsl/lib/libcuda.so 2>/dev/null || true
    ln -sf "${CUDA_1}" /usr/local/lib/libcuda.so 2>/dev/null || true
fi
ldconfig 2>/dev/null || true
