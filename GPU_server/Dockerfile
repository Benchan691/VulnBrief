FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gpu_config.py gpu_worker.py ./
COPY config/gpu_server.json config/gpu_server.json

CMD ["python", "gpu_worker.py"]
