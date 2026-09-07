# Kestrel Pay API — lab image. Small, single-stage.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 KESTREL_LOG_DIR=/var/log/kestrel
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY seed.py .
RUN mkdir -p /var/log/kestrel /app/data
EXPOSE 8080
# Default = vulnerable mode. Set KESTREL_HARDENED=1 for the remediated build.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
