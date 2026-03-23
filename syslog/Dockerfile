FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir httpx

COPY . .

CMD ["python", "syslog_receiver.py"]
