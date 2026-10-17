FROM python:3.12-slim

# System dependencies for Tesseract OCR
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-hin \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directory and permissions
RUN mkdir -p data && chmod +x scripts/entrypoint.sh

# Expose ports: 8501 (Streamlit UI), 8000 (FastAPI REST service)
EXPOSE 8501 8000

# Health check (checks Streamlit or FastAPI depending on active mode)
HEALTHCHECK --interval=30s --timeout=10s \
    CMD python -c "import requests; requests.get('http://localhost:8501/_stcore/health' if not requests.get('http://localhost:8000/health').ok else 'http://localhost:8000/health')" || exit 1

# Default entrypoint supports APP_SERVICE=streamlit, api, or both
ENTRYPOINT ["bash", "scripts/entrypoint.sh"]
