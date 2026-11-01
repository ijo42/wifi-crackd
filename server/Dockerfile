FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        hashcat \
        hcxtools \
        ocl-icd-libopencl1 \
        libnvrtc12 \
        python3 \
        python3-venv \
        python3-pip \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

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
