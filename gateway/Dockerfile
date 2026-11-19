FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway_app ./gateway_app
COPY wsgi.py openapi.yaml ./

# Run as an unprivileged user; /data holds the gateway's own SQLite database.
RUN useradd --create-home --uid 10001 appuser && mkdir -p /data /logs && chown appuser:appuser /data /logs
USER appuser

EXPOSE 9000
CMD ["gunicorn", "--bind", "0.0.0.0:9000", "--workers", "1", "--threads", "8", "wsgi:app"]
