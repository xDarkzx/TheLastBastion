FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install the SDK from source
COPY sdk/ /app/sdk/
RUN pip install --no-cache-dir -e /app/sdk/

# Copy demo agent code
COPY demo_agent/ /app/

EXPOSE 3100

CMD ["python", "web.py"]
