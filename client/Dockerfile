FROM python:3.12-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
        wireguard-tools \
        iproute2 \
        iputils-ping \
        curl \
        openresolv \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir cryptography

ENV PYTHONPATH=/workspace

CMD ["sleep", "infinity"]
