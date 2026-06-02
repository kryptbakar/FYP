FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_DEFAULT_TIMEOUT=180 PIP_RETRIES=10
WORKDIR /app
COPY services/intel-enricher/requirements.txt .
# pySigma is optional at runtime (sigma_eval falls back); don't fail the image if it
# can't be fetched on a flaky link.
RUN pip install --no-cache-dir psycopg[binary]==3.2.3 httpx==0.28.1 pyyaml==6.0.2 \
 && (pip install --no-cache-dir pysigma==0.11.18 pysigma-backend-opensearch==1.1.4 \
     || echo "WARN: pySigma not installed; sigma_eval will use the x_opensearch_query fallback")
COPY services/intel-enricher/ ./
ENTRYPOINT ["python", "main.py"]
