FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    GEMINI_WEB2API_CONFIG=/app/config.json
WORKDIR /app


COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache/pip \
    python -m pip install --no-cache-dir -r requirements.txt

COPY gemini_web2api/ ./gemini_web2api/
#COPY config.example.json ./config.json 

RUN useradd --create-home --uid 10001 appuser && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8081/', timeout=5).status == 200 else 1)"

CMD ["python", "-m", "gemini_web2api", "--config", "/app/config.json"]
