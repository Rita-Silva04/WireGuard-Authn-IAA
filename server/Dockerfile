FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*
COPY srvauthn/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY srvauthn/ ./srvauthn/
COPY db/ ./db/
ENV PYTHONPATH=/app
CMD ["python", "-m", "srvauthn.srvauthn", "--config", "/app/srvauthn/srvauthn.conf"]
