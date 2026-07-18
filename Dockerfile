# The Last Bastion — API Image
FROM python:3.11-slim

WORKDIR /app

# System deps for image forensics + PDF analysis
RUN apt-get update && apt-get install -y \
    libgl1 \
    libglib2.0-0 \
    tesseract-ocr \
    tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the Bastion Protocol SDK -- core/agent_simulator.py, core/border_agent.py,
# core/m2m_router.py etc. all `from lastbastion import ...`, but that package lives
# at sdk/lastbastion/, not the repo root, so it's invisible to Python unless
# installed. Without this, the API container boots (imports are deferred/guarded
# where they touch lastbastion) but the entire Bastion Protocol agent overlay
# silently fails to start -- _boot_bastion_servers() logs a warning and returns
# False, and every agent trade in the demo is dead with no visible error.
RUN pip3 install --no-cache-dir -e sdk/

# Runtime config
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379

CMD ["python3", "-m", "uvicorn", "regional_core:app", "--host", "0.0.0.0", "--port", "8000"]
