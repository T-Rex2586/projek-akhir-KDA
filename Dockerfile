FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    tshark \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Upgrade pip and pin setuptools for Ryu compatibility
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir setuptools==57.5.0 wheel pbr && \
    PBR_VERSION=4.34 pip install --no-cache-dir --no-build-isolation -r requirements.txt

# Copy project files
COPY . .

# Create necessary directories
RUN mkdir -p \
    models \
    logs \
    output \
    data/raw \
    data/processed

# Default command
CMD ["python", "-m", "src.lucid_RF", "--help"]