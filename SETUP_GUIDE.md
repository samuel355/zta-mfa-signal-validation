# Multi-Source MFA ZTA Framework - Setup Guide

This guide walks you through setting up and running the Multi-Source MFA Zero Trust Architecture framework with both the proposed system and baseline comparison.

## 🏗️ Architecture Overview

The framework consists of:
- **Proposed Framework**: Advanced ZTA system with multi-source validation
- **Baseline Framework**: Traditional MFA system for comparison
- **Data Sources**: CICIDS, WiFi, Device Posture, TLS fingerprints
- **Database**: PostgreSQL with ZTA schema for metrics and comparisons
- **Simulator**: Enhanced simulator that feeds data to both frameworks

## 📋 Prerequisites

### Required Software
- Docker and Docker Compose
- PostgreSQL database (Supabase recommended)
- Python 3.11+ (for local development)

### Required Data
Ensure you have the following data files in the `data/` directory:
```
data/
├── cicids/                     # CICIDS network traffic datasets
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   └── ... (other CICIDS files)
├── wifi/
│   └── wigle_sample.csv       # WiFi BSSID and location data
├── device_posture/
│   └── device_posture.csv     # Device security posture data
├── tls/
│   └── ja3_fingerprints.csv   # TLS fingerprint data
└── geolite2/
    └── GeoLite2-City.mmdb     # GeoIP database
```

## 🔧 Setup Steps

### Step 1: Database Setup

1. **Create Database Schema**
   ```bash
   # Connect to your PostgreSQL database and run:
   psql -h your_host -U your_user -d your_db -f database/schema_extension.sql
   ```

2. **Test Database Connection**
   ```bash
   export DB_DSN="postgresql://user:password@host:5432/database"
   python scripts/test_db_connection.py
   ```

### Step 2: Environment Configuration

1. **Copy Environment Template**
   ```bash
   cp .env.sample compose/.env
   ```

2. **Update compose/.env with your settings:**
   ```bash
   # Database Configuration
   DB_DSN=postgresql://your_user:your_password@your_host:5432/your_db
   PGOPTIONS=-c search_path=zta,public
   
   # Elasticsearch (if using)
   ELASTIC_VERSION=8.11.0
   ELASTIC_PASSWORD=your_elastic_password
   
   # Other configurations...
   ```

### Step 3: Build and Run

1. **Build and Start All Services**
   ```bash
   cd compose/
   docker compose up --build
   ```

2. **Expected Services**
   - `zta_validation` (port 8001)
   - `zta_trust` (port 8002)  
   - `zta_gateway` (port 8003)
   - `zta_siem` (port 8010)
   - `zta_baseline` (port 8020)
   - `zta_metrics` (port 8030)
   - `zta_simulator` (runs once, then exits)

### Step 4: Verify Operation

1. **Check Service Health**
   ```bash
   curl http://localhost:8001/health  # Validation
   curl http://localhost:8003/health  # Gateway
   curl http://localhost:8020/health  # Baseline
   ```

2. **Check Database for Data**
   ```sql
   -- Check if data is being inserted
   SELECT COUNT(*) FROM zta.baseline_decisions;
   SELECT COUNT(*) FROM zta.framework_comparison;
   
   -- View recent decisions
   SELECT * FROM zta.framework_comparison ORDER BY created_at DESC LIMIT 10;
   ```

## 📊 Data Flow

### Automatic Data Insertion Process

1. **Simulator Startup**: The enhanced simulator waits for all services to be ready
2. **Data Generation**: Creates realistic signals from CICIDS, WiFi, device, and TLS data
3. **Dual Framework Testing**: Each signal is processed by both:
   - **Proposed Framework**: `Validation → Trust → Gateway`
   - **Baseline Framework**: `Direct → Baseline Service`
4. **Database Storage**: Results stored in comparison tables for analysis

### Data Tables

- `zta.baseline_decisions` - Baseline framework decisions
- `zta.baseline_auth_attempts` - Authentication attempts
- `zta.framework_comparison` - Side-by-side comparisons
- `zta.performance_metrics` - Timing and performance data
- `zta.security_classifications` - Threat detection accuracy

## 🔍 Monitoring and Analysis

### View Metrics Dashboard
```bash
# Get baseline statistics
curl http://localhost:8020/stats

# Get comparison data
curl http://localhost:8020/comparison

# Get metrics service data
curl http://localhost:8030/metrics
```

### Database Queries for Analysis
```sql
-- Framework comparison summary
SELECT * FROM zta.daily_comparison_summary;

-- Security accuracy comparison
SELECT * FROM zta.security_accuracy_summary;

-- Performance comparison
SELECT 
    framework_type,
    AVG(processing_time_ms) as avg_processing_time,
    COUNT(*) as total_decisions
FROM zta.framework_comparison 
WHERE created_at > NOW() - INTERVAL '1 hour'
GROUP BY framework_type;
```

## 🐛 Troubleshooting

### Common Issues

#### 1. No Data Being Inserted
**Symptoms**: Database tables are empty after running simulator
**Solutions**:
- Check service health endpoints
- Verify database connection with test script
- Check simulator logs: `docker logs zta_simulator`
- Ensure data files exist in correct locations

#### 2. Services Not Starting
**Symptoms**: Docker containers exit or fail to start
**Solutions**:
- Check `.env` file configuration
- Verify database connectivity
- Check port conflicts
- Review logs: `docker compose logs [service_name]`

#### 3. Database Connection Issues
**Symptoms**: Connection errors in logs
**Solutions**:
- Verify DSN format: `postgresql://user:pass@host:port/db`
- Check firewall/network access
- Ensure SSL mode is correct
- Test with: `python scripts/test_db_connection.py`

#### 4. Missing Data Files
**Symptoms**: Simulator generates minimal data
**Solutions**:
- Verify data directory structure
- Check file permissions
- Download missing datasets
- Use sample data if available

### Debug Mode

Run simulator manually with debug output:
```bash
# Run enhanced simulator manually
docker compose run simulator python /app/scripts/simulator/run_enhanced.py --verbose --samples 10

# Skip health checks for faster testing
docker compose run simulator python /app/scripts/simulator/run_enhanced.py --skip-health-check --samples 5
```

### Log Analysis
```bash
# View all logs
docker compose logs

# View specific service logs
docker compose logs validation
docker compose logs baseline
docker compose logs simulator

# Follow logs in real-time
docker compose logs -f simulator
```

## 📈 Performance Tuning

### Simulator Configuration
Adjust these environment variables in `.env`:
```bash
SIM_SLEEP=0.5          # Faster data generation
SIM_MAX_SAMPLES=500    # More samples
SIM_BENIGN_KEEP=0.2    # Keep more benign samples
```

### Database Optimization
```sql
-- Add indexes for better query performance
CREATE INDEX CONCURRENTLY idx_framework_comparison_created_at_desc 
ON zta.framework_comparison (created_at DESC);

-- Clean up old data
DELETE FROM zta.framework_comparison WHERE created_at < NOW() - INTERVAL '30 days';
```

## 🔄 Continuous Operation

### Automated Data Generation
The simulator runs once and generates a batch of data. For continuous operation:

1. **Cron-based Execution**
   ```bash
   # Add to crontab for hourly data generation
   0 * * * * cd /path/to/framework && docker compose run --rm simulator
   ```

2. **Long-running Simulator**
   ```bash
   # Run with more samples and longer operation
   docker compose run simulator python /app/scripts/simulator/run_enhanced.py --samples 1000 --sleep 2.0
   ```

## 📚 API Documentation

### Baseline Service Endpoints
- `GET /health` - Service health check
- `POST /decision` - Make MFA decision
- `GET /stats?hours=24` - Get decision statistics
- `GET /comparison?hours=24` - Get comparison metrics

### Proposed Framework Endpoints
- `POST /validate` (port 8001) - Validate signals
- `POST /decision` (port 8003) - Make ZTA decision
- `GET /metrics` (port 8030) - Get system metrics

## 🎯 Expected Results

After successful setup and execution:
- Both frameworks process the same input signals
- Database contains comparison data showing:
  - Decision accuracy differences
  - Performance timing comparisons
  - Threat detection effectiveness
- Metrics available for research analysis and evaluation

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review service logs for specific error messages
3. Verify your data files match the expected format
4. Test database connectivity independently
5. Ensure all environment variables are correctly set

The framework is designed to be robust and provide meaningful comparison data between traditional MFA and advanced ZTA approaches.