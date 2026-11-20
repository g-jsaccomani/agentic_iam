# Must match the Python that requirements.lock was frozen from and tested with (see its header).
# The lock does not install on 3.11 (e.g. contourpy==1.4.0 requires Python >= 3.12).
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    GOOGLE_GENAI_USE_VERTEXAI=TRUE \
    GOOGLE_CLOUD_LOCATION=global \
    GEMINI_MODEL=gemini-3.1-pro-preview-customtools

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.lock requirements.txt ./
RUN pip install --no-cache-dir -r requirements.lock

COPY . .

RUN useradd --create-home --uid 10001 appuser && \
    mkdir -p /app/exports && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
