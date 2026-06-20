# SOC Central API — Phase 0 skeleton.
# Slim, single-stage image. Multi-stage + non-root hardening lands in Phase 8.
FROM python:3.12-slim

# Don't write .pyc, unbuffered stdout for clean container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install deps first for better layer caching.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create an unprivileged user to run the service.
RUN useradd --create-home --uid 10001 appuser
COPY app ./app
USER appuser

EXPOSE 8000

# Healthcheck hits the liveness endpoint.
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
