# Bayora Sentinel broker -- runs as a non-root user.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN useradd --system --create-home --uid 10001 sentinel

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
USER sentinel

EXPOSE 8000
# The broker reaches the AI container at AI_URL on the internal Docker network.
ENV AI_URL=http://ai:11434
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
