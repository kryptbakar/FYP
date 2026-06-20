# risk-engine: composite scoring + XGBoost/SHAP. Build context = ml/ dir.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# libgomp1 is needed by the XGBoost runtime.
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
# Split installs so each large wheel caches independently across rebuilds (the link
# here is slow/flaky); raise pip's socket timeout + retries.
ENV PIP_DEFAULT_TIMEOUT=180 PIP_RETRIES=10 PIP_PREFER_BINARY=1
RUN pip install --no-cache-dir numpy==1.26.4 scipy==1.13.1
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3"
RUN pip install --no-cache-dir xgboost==1.7.6
COPY . ./
# default: score on a loop (no-op-ish until a model is trained)
ENTRYPOINT ["python", "run.py"]
CMD ["score", "--loop"]
