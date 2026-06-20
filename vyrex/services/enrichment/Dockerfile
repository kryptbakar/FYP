# enrichment engine. Reads telemetry + feed mirror, writes findings. No internet.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/enrichment/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/enrichment/ ./
RUN useradd --uid 10001 appuser
USER appuser
ENTRYPOINT ["python", "main.py"]
