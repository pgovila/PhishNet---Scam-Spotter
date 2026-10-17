#!/usr/bin/env bash
set -e

# Support running Streamlit (default), FastAPI, or both in container
MODE="${APP_SERVICE:-streamlit}"

if [ "$MODE" = "api" ]; then
    echo "Starting PhishNet FastAPI service on port 8000..."
    exec uvicorn api:app --host 0.0.0.0 --port 8000
elif [ "$MODE" = "both" ]; then
    echo "Starting PhishNet FastAPI on port 8000 (background) and Streamlit on port 8501..."
    uvicorn api:app --host 0.0.0.0 --port 8000 &
    exec streamlit run app.py --server.port=8501 --server.address=0.0.0.0
else
    echo "Starting PhishNet Streamlit UI on port 8501..."
    exec streamlit run app.py --server.port=8501 --server.address=0.0.0.0
fi
