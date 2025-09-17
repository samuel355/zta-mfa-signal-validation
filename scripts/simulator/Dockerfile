# scripts/simulator/Dockerfile
FROM python:3.11-slim

# Install system dependencies for PostgreSQL client
RUN apt-get update && apt-get install -y \
  libpq-dev \
  gcc \
  && rm -rf /var/lib/apt/lists/*

# Inside the container we'll use /app (created automatically)
WORKDIR /app

# Install simulator deps
# Build context will be the repo root (see compose below), so these paths resolve.
COPY scripts/simulator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the simulator code
COPY scripts/simulator /app/scripts/simulator

# Default command: run the startup script that waits for services and then runs the enhanced simulator
CMD ["python", "/app/scripts/simulator/start_simulation.py"]
