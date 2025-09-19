# Multi-Source MFA Zero Trust Architecture Framework

## Quick Start

### Prerequisites
- Docker and Docker Compose
- At least 4GB RAM available for containers

### Environment Setup (Optional)
```bash
# Copy sample environment file
cp .env.sample .env

# Edit .env file with your settings (optional)
# Default values work for basic testing
```

### Run the System
```bash
# Navigate to compose directory
cd compose

# Start all services
docker compose up -d

# View logs (optional)
docker compose logs -f
```

### Services
- **Validation Service**: http://localhost:8001
- **Trust Service**: http://localhost:8002  
- **Gateway Service**: http://localhost:8003
- **SIEM Service**: http://localhost:8010
- **Baseline Service**: http://localhost:8020
- **Metrics Service**: http://localhost:8030
- **Elasticsearch**: http://localhost:9200
- **Kibana**: http://localhost:5601

### Test the Framework
```bash
# Test baseline framework
curl -X POST http://localhost:8020/decision \
  -H 'Content-Type: application/json' \
  -d '{"signals":{"session_id":"test","ip_geo":{"ip":"192.168.1.1"},"label":"BENIGN"}}'

# Test proposed framework  
curl -X POST http://localhost:8003/decision \
  -H 'Content-Type: application/json' \
  -d '{"validated":{"vector":{"session_id":"test","label":"BENIGN"},"weights":{"gps":0.8},"reasons":[]}}'

# View comparison metrics
curl http://localhost:8030/metrics/comparison
```

### Access Kibana
1. Open http://localhost:5601
2. Login: `elastic` / `changeme`
3. View indices: `mfa-events`, `baseline-decisions`, `siem-alerts`

### Stop Services
```bash
cd compose
docker compose down
```

### Environment Variables
Key variables (all have working defaults):
- `ELASTIC_PASSWORD`: Elasticsearch password (default: changeme)
- `DB_DSN`: Database connection string
- `ES_HOST`, `ES_USER`, `ES_PASS`: Elasticsearch connection
- Baseline risk weights: `BASELINE_*_WEIGHT` variables

## Architecture
- **Proposed Framework**: Raw signals → Validation → Trust scoring → Decision
- **Baseline Framework**: Raw signals → Simple rules → Decision
- Both frameworks store results in database and Elasticsearch for comparison

The system automatically generates comparison data between the two approaches for analysis.