# The Last Bastion — API Image
FROM python:3.11-slim

WORKDIR /app

# System deps for image forensics + PDF analysis
RUN apt-get update && apt-get install -y \
    libgl1-mesa-glx \
    libglib2.0-0 \
    tesseract-ocr \
    tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Runtime config
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379

CMD ["python3", "-m", "uvicorn", "regional_core:app", "--host", "0.0.0.0", "--port", "8000"]
