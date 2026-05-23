FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpam-dev libcurl4-openssl-dev make \
    && rm -rf /var/lib/apt/lists/*

COPY idp/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idp/ ./idp/
COPY common/ ./common/

RUN mkdir -p /data
ENV PYTHONPATH=/app

CMD ["python", "-m", "idp.app"]
