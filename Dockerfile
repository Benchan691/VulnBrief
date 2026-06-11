FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV APP_CONFIG=/app/config/config.json

CMD ["gunicorn", "-c", "gunicorn_config.py", "app:app"]
