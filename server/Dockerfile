FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 iptables procps sqlite3 \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ ./server/
COPY common/ ./common/

RUN chmod +x /app/server/entrypoint.sh
ENV PYTHONPATH=/app

ENTRYPOINT ["/app/server/entrypoint.sh"]
