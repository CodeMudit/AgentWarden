FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

ENV HOST=0.0.0.0
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
EXPOSE 8000

# Run migrations-ish via create_all on startup (init_db in lifespan)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
