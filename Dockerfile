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

CMD ["python", "-m", "gemini_web2api", "--config", "/app/config.json"]
