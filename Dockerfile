FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TB_ALLOW_BYOK=0 TB_PUBLIC_RATE_LIMIT=1
RUN apt-get update && apt-get install --no-install-recommends -y tesseract-ocr && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY trustboundary/ ./trustboundary/
COPY web/ ./web/
COPY reports/ ./reports/
RUN useradd -m appuser && mkdir -p /app/data && chown -R appuser:appuser /app/data /app/reports
USER appuser
EXPOSE 7860
CMD ["uvicorn","trustboundary.api:app","--host","0.0.0.0","--port","7860"]
