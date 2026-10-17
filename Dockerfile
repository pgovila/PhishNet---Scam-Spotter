FROM python:3.11-slim

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

# Create data directory
RUN mkdir -p data

# Expose ports
EXPOSE 8501 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s \
    CMD python -c "import requests; requests.get('http://localhost:8501/_stcore/health')" || exit 1

# Default: run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
