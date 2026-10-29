FROM python:3.11-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY scanner/ scanner/
COPY src/ src/
COPY static/ static/
COPY frontend/ frontend/
COPY run_scan.py .

# Expose port
EXPOSE 8000

# Default: run the API server
CMD ["uvicorn", "scanner.api:app", "--host", "0.0.0.0", "--port", "8000"]
