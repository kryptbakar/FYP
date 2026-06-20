FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/sensor-bridge/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/sensor-bridge/ ./
ENTRYPOINT ["python", "bridge.py"]
