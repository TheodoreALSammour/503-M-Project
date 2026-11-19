FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY wsgi.py entrypoint.sh ./
RUN sed -i 's/\r$//' entrypoint.sh && chmod +x entrypoint.sh

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser && mkdir -p /logs && chown appuser:appuser /logs
USER appuser

EXPOSE 8000
ENTRYPOINT ["./entrypoint.sh"]
