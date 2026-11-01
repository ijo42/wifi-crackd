FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ARG: версия hashcat с hashcat.net (официальный бинарь с CUDA-бэкендом;
# apt-пакет Ubuntu запаздывает и собран без CUDA)
ARG HASHCAT_VERSION=8.0.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        hcxtools \
        ocl-icd-libopencl1 \
        libnvrtc12 \
        p7zip-full \
        python3 \
        python3-venv \
        python3-pip \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# официальный бинарь hashcat (включает CUDA; apt-пакет — только OpenCL)
RUN curl -fsSL -o /tmp/hashcat.7z "https://hashcat.net/files/hashcat-${HASHCAT_VERSION}.7z" \
    && 7z x -o/opt/hashcat /tmp/hashcat.7z > /dev/null \
    && rm /tmp/hashcat.7z \
    && ln -s hashcat-${HASHCAT_VERSION} /opt/hashcat/current \
    && ln -s /opt/hashcat/current/hashcat.bin /usr/local/bin/hashcat \
    && hashcat --version | head -1

ENV HASHCAT_BIN=/opt/hashcat/current/hashcat.bin

WORKDIR /app

COPY server/requirements.txt /app/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r /app/requirements.txt

COPY server/app /app/app
COPY config.example.yaml /app/config.yaml
COPY server/entrypoint.sh /entrypoint.sh
COPY server/fix-gpu.sh /fix-gpu.sh
RUN chmod +x /entrypoint.sh /fix-gpu.sh \
    && useradd --system --create-home --shell /usr/sbin/nologin crackd \
    && mkdir -p /data && chown -R crackd:crackd /data /app

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
