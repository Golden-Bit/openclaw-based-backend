# syntax=docker/dockerfile:1
FROM python:3.12-slim

# Prevent Python from writing .pyc files and buffer logs
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (build tools only if you add native deps)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app /app/app
COPY README.md /app/README.md

# Expose FastAPI
EXPOSE 8000

# Uvicorn entrypoint
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
