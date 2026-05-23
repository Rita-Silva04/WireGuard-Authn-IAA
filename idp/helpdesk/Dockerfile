FROM python:3.12-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*
COPY helpdesk/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY helpdesk/ ./helpdesk/
COPY db/ ./db/
RUN mkdir -p /data
ENV PYTHONPATH=/app
CMD ["python", "-m", "helpdesk.app"]
