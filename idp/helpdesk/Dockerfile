FROM python:3.12-slim
WORKDIR /app

COPY idp/helpdesk/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idp/helpdesk/ ./helpdesk/
COPY common/ ./common/

RUN mkdir -p /data
ENV PYTHONPATH=/app

CMD ["python", "-m", "helpdesk.app"]
