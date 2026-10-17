# Single image used for both the API and the dashboard (see docker-compose.yml).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ src/
COPY dashboard/ dashboard/
COPY config/ config/
COPY evaluation/ evaluation/
COPY .streamlit/ .streamlit/
COPY app.py .

# Run as an unprivileged user; only logs/ and config/ need to be writable.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p logs \
    && chown -R appuser:appuser logs config
USER appuser

EXPOSE 8000 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)"

CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
