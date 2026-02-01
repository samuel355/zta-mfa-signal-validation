# Steps to Start the Application

## Prerequisites

- **Docker** and **Docker Compose**
- **PostgreSQL** (external; e.g. Supabase). The stack does not run Postgres in Docker.
- **4GB+ RAM** (8GB+ recommended). For Elasticsearch on Linux:  
  `sudo sysctl -w vm.max_map_count=262144`

---

## 1. Configure environment

From the project root:

```bash
# If you don't have .env yet, copy from sample and edit
cp .env.sample .env

# Required: set DB_DSN to your PostgreSQL (Supabase or local)
# Example: DB_DSN=postgresql://user:pass@host:5432/dbname
```

Ensure `.env` has at least:

- `DB_DSN` – PostgreSQL connection string
- `ELASTIC_VERSION` (e.g. `8.12.2`) if not in `.env.sample`
- `ELASTIC_PASSWORD`, `KIBANA_SYSTEM_PASSWORD` if your compose expects them

---

## 2. Prepare the database

Apply the schema once (if the `zta` schema and tables are not created yet):

```bash
# Option A: using psql
psql "$DB_DSN" -f database/database.sql

# Option B: from Python (if psycopg is installed)
python3 -c "
import os
import psycopg
dsn = os.getenv('DB_DSN', 'postgresql://postgres:postgres@localhost:5432/postgres')
with psycopg.connect(dsn) as c:
    c.execute(open('database/database.sql').read())
"
```

---

## 3. (Optional) Data files for validation and simulator

Required by the **validation** service and the **simulator**:

- `data/wifi/wigle_sample.csv`
- `data/device_posture/device_posture.csv`
- `data/tls/ja3_fingerprints.csv`

Optional: `data/cicids/*.csv`, `data/geolite2/GeoLite2-City.mmdb`

If these are missing, create the directories and add placeholders or real data; otherwise validation/simulator may fail.

---

## 4. Start all services

Run from the **project root** so `compose/docker-compose.yml` and `.env` are found:

```bash
docker compose -f compose/docker-compose.yml up -d
```

This starts:

| Service      | Port | Purpose                          |
|-------------|------|----------------------------------|
| Elasticsearch | 9200 | Search/analytics                 |
| Kibana      | 5601 | Dashboards                       |
| Validation  | 8001 | Signal validation & enrichment   |
| Trust       | 8002 | Risk scoring                     |
| Gateway     | 8003 | Request orchestration, main API  |
| SIEM        | 8010 | Security event correlation       |
| Baseline    | 8020 | Baseline MFA                     |
| Metrics     | 8030 | Framework comparison metrics     |
| Indexer     | —    | Elasticsearch indexing (no port) |
| Simulator   | —    | Test traffic (no port)           |

---

## 5. Wait for services

Elasticsearch can take 1–2 minutes to become ready.

```bash
# Wait until Elasticsearch is green or yellow
curl -s "http://localhost:9200/_cluster/health?pretty"

# Optional: wait until Gateway responds
until curl -s -o /dev/null -w "%{http_code}" http://localhost:8003/health | grep -q 200; do
  sleep 2
done
```

---

## 6. Health checks

```bash
curl http://localhost:8001/health   # Validation
curl http://localhost:8002/health   # Trust
curl http://localhost:8003/health   # Gateway
curl http://localhost:8010/health   # SIEM
curl http://localhost:8020/health   # Baseline
curl http://localhost:8030/health   # Metrics
```

---

## 7. (Optional) Generate thesis metrics and data

If you use the thesis metrics and related tables:

```bash
# Generate thesis metrics (run where DB_DSN and DB are reachable)
export DB_DSN="postgresql://..."   # or ensure .env is loaded
python3 generate_thesis_metrics.py

# Populate security classifications
python3 populate_security_classifications.py
```

If the indexer runs in `continuous` mode (default), it will keep syncing DB → Elasticsearch. To run it once:

```bash
docker exec zta_indexer python3 unified_indexer.py once
# or whatever the indexer's CLI supports, e.g. INDEXER_MODE=once
```

---

## 8. Access points

| Resource        | URL                      |
|----------------|--------------------------|
| Kibana         | http://localhost:5601    |
| Gateway API    | http://localhost:8003    |
| Metrics API    | http://localhost:8030    |
| Elasticsearch  | http://localhost:9200    |

---

## One-command setup (alternative)

The `setup_framework.py` script automates several steps. It may fail if some referenced scripts or indexers are missing or renamed:

```bash
python3 setup_framework.py
```

Use this only if you’ve verified it matches your repo (e.g. `scripts/generate_framework_data.py`, `services/indexer/framework_indexer.py`). Otherwise follow the manual steps above.

---

## Stopping

```bash
docker compose -f compose/docker-compose.yml down
```

---

## Troubleshooting

| Issue | What to do |
|-------|------------|
| Elasticsearch won’t start (Linux) | `sudo sysctl -w vm.max_map_count=262144` |
| `connection refused` to DB | Check `DB_DSN`, ensure Postgres is running and reachable |
| Validation/simulator errors about missing files | Add `data/wifi`, `data/device_posture`, `data/tls` (and optional `data/cicids`, `data/geolite2`) |
| No data in Kibana | Ensure indexer is running and DB has data; check `INDEXER_MODE` and indexer logs |
