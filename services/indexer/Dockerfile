FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
  postgresql-client \
  curl \
  && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the indexer script
COPY elasticsearch-indexer.py .

# Create non-root user
RUN useradd -m -u 1001 indexer && chown -R indexer:indexer /app
USER indexer

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://elasticsearch:9200/_cluster/health || exit 1

# Run indexer in continuous mode
CMD ["python", "elasticsearch-indexer.py", "continuous", "5", "1"]
