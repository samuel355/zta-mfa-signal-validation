# Database Tables and Elasticsearch Indices Summary

## PostgreSQL Database Tables (Schema: zta)

### Tables Currently Being Used for Data Insertion

| Table Name | Purpose | Data Inserted By | Key Use Case |
|------------|---------|------------------|--------------|
| **zta.thesis_metrics** | Stores comprehensive metrics for framework comparison | `generate_framework_data.py`, decision engines | Primary metrics storage for both frameworks |
| **zta.framework_comparison** | Side-by-side framework performance data | `generate_framework_data.py`, `enhanced_sim.py` | Comparative analysis |
| **zta.framework_performance_comparison** | Aggregated performance metrics | `generate_framework_data.py` | Overall framework statistics |
| **zta.baseline_decisions** | Baseline MFA framework decisions | `baseline/app/main.py` | Baseline authentication tracking |
| **zta.baseline_auth_attempts** | Authentication attempts in baseline | `baseline/app/main.py` | Baseline attempt logging |
| **zta.baseline_trusted_devices** | Trusted device registry | `baseline/app/main.py` | Device trust management |
| **zta.validated_context** | Validated and enriched signals | `validation/app/main.py` | Signal validation storage |
| **zta.trust_decisions** | Risk scoring and trust decisions | `trust/app/main.py` | Trust evaluation results |
| **zta.siem_alerts** | Security event correlation | `siem/app/main.py`, `generate_framework_data.py` | STRIDE threat mapping |
| **zta.stride_threat_simulation** | STRIDE detection accuracy | `generate_framework_data.py` | Threat detection metrics |
| **zta.security_classifications** | Threat prediction accuracy | `enhanced_sim.py` | Classification tracking |
| **zta.mfa_events** | MFA challenge events | `gateway/app/main.py` | MFA event logging |
| **zta.network_latency_simulation** | Network condition testing | `generate_framework_data.py` | Performance under conditions |
| **zta.session_continuity_metrics** | Session continuity tracking | Framework metrics collectors | User experience metrics |
| **zta.performance_metrics** | Service-level performance | Various services | Performance tracking |
| **zta.metrics_cache** | Cached calculated metrics | `metrics/app/main.py` | Performance optimization |

### Tables Not Currently Used (Available for Future)
- None - all tables are actively used

## Elasticsearch Indices

### Active Indices Created by framework_indexer.py

| Index Name | Purpose | Key Fields | Visualization Use |
|------------|---------|------------|-------------------|
| **framework-comparison** | Real-time framework comparison | framework_type, decision, risk_score | Comparison charts |
| **security-metrics** | Security accuracy metrics | tpr, fpr, precision, recall, f1_score | Accuracy bar charts |
| **user-experience** | User experience metrics | stepup_challenge_rate_pct, friction_index, continuity_pct | UX comparison |
| **privacy-metrics** | Privacy compliance metrics | compliance_pct, retention_days, leakage_pct | Privacy dashboard |
| **performance-metrics** | System performance metrics | avg_decision_latency_ms, throughput_rps | Performance graphs |
| **stride-alerts** | STRIDE threat detection | stride_category, severity, alert_count | Threat distribution |
| **failed-logins** | Failed authentication timeline | hour_of_day, baseline_count, proposed_count | Timeline visualization |
| **decision-latency** | Latency under network conditions | network_latency_ms, decision_latency_ms | Latency comparison |
| **validation-logs** | Signal validation logs | mismatch_count, validation_score, signal_quality | Validation effectiveness |

### Additional Indices Created by Services

| Index Name | Created By | Purpose |
|------------|------------|---------|
| **mfa-events** | gateway/app/main.py | MFA authentication events |
| **siem-alerts** | gateway/app/main.py | Security alerts from SIEM |

## Data Flow Mapping

### 1. Database → Elasticsearch Flow
```
PostgreSQL Tables
    ↓
framework_indexer.py (reads from DB)
    ↓
Elasticsearch Indices
    ↓
Kibana Dashboards
```

### 2. Service → Database Flow
```
Authentication Request → Services → PostgreSQL Tables

Validation Service → zta.validated_context
Trust Service → zta.trust_decisions
Gateway Service → zta.mfa_events
SIEM Service → zta.siem_alerts
Baseline Service → zta.baseline_decisions, zta.baseline_auth_attempts
```

### 3. Data Generation Flow
```
generate_framework_data.py creates:
├── zta.thesis_metrics (authentication sessions)
├── zta.framework_comparison (comparison data)
├── zta.framework_performance_comparison (aggregated metrics)
├── zta.network_latency_simulation (latency testing)
├── zta.stride_threat_simulation (threat detection)
└── zta.siem_alerts (security events)
```

## Key Metrics Generated

### Security Metrics (Stored & Indexed)
- **True Positive Rate (TPR)**: 87% baseline → 93% proposed (+6.9%)
- **False Positive Rate (FPR)**: 11% baseline → 4% proposed (-63.6%)
- **Precision**: 78% baseline → 91% proposed (+16.7%)
- **Recall**: 87% baseline → 93% proposed (+6.9%)
- **F1 Score**: 82% baseline → 92% proposed (+12.2%)

### User Experience Metrics (Stored & Indexed)
- **Step-up Challenge Rate**: 19.4% baseline → 8.7% proposed (-55.2%)
- **User Friction Index**: 14/100 baseline → 5/100 proposed (-64.3%)
- **Session Continuity**: 82.1% baseline → 94.6% proposed (+15.2%)

### Privacy Metrics (Stored & Indexed)
- **Compliance**: 62% baseline → 91% proposed (+46.8%)
- **Data Retention**: 14 days baseline → 3 days proposed (-78.6%)
- **Privacy Leakage**: 9.5% baseline → 2.1% proposed (-77.9%)

### Performance Metrics (Stored & Indexed)
- **Average Latency**: 112ms baseline → 148ms proposed (+32.1%)
- **95th Percentile Latency**: 185ms baseline → 214ms proposed (+15.7%)
- **Throughput**: 840 req/s baseline → 765 req/s proposed (-8.9%)

## Verification Checklist

### Database Tables ✅
- [x] All 17 tables defined in database.sql
- [x] All tables have appropriate constraints
- [x] Foreign key relationships not enforced (flexibility)
- [x] JSONB columns for flexible data storage
- [x] Timestamp columns with timezone

### Elasticsearch Indices ✅
- [x] 9 primary indices in framework_indexer.py
- [x] 2 additional indices from services
- [x] All indices have proper mappings
- [x] Timestamp fields for time-based queries
- [x] Keyword fields for aggregations

### Data Insertion Points ✅
- [x] generate_framework_data.py populates 6 tables
- [x] Services populate 9 tables during runtime
- [x] Simulator populates 2 tables
- [x] All INSERT statements use parameterized queries

### Indexing Pipeline ✅
- [x] framework_indexer.py reads from PostgreSQL
- [x] Continuous indexing mode available
- [x] Batch processing support
- [x] Error handling and retry logic

## Quick Reference Commands

### Check Table Data
```sql
-- Count records in key tables
SELECT 'thesis_metrics' as table_name, COUNT(*) FROM zta.thesis_metrics
UNION ALL
SELECT 'framework_comparison', COUNT(*) FROM zta.framework_comparison
UNION ALL
SELECT 'siem_alerts', COUNT(*) FROM zta.siem_alerts;
```

### Check Elasticsearch Indices
```bash
# List all indices
curl -X GET "localhost:9200/_cat/indices?v&s=index"

# Check document count
curl -X GET "localhost:9200/security-metrics/_count"
```

### Generate Test Data
```bash
# Generate framework comparison data
python scripts/generate_framework_data.py

# Start continuous indexing
python services/indexer/framework_indexer.py
```

### View in Kibana
```
http://localhost:5601
Dashboard: Multi-Source MFA Framework Analysis
```

## Notes

1. **Table Naming**: The table `thesis_metrics` contains framework metrics data and is appropriately named for its purpose
2. **Schema**: All tables use the `zta` schema for organization
3. **Indices**: Elasticsearch indices use hyphenated names for consistency
4. **Data Types**: PostgreSQL uses JSONB for flexible fields, Elasticsearch uses appropriate field mappings
5. **Performance**: Indexer runs every 30 seconds by default, configurable via environment variables