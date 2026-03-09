FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir "a2a-sdk[http-server]"

# Copy project
COPY . .

# Expose all agent ports
EXPOSE 9001 9002 9003 9004

# Start all 4 agents in one container
CMD ["python", "agents/a2a/agent_runner.py"]
