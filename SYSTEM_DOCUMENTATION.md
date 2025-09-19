# Multi-Source MFA Zero Trust Architecture Framework - Comprehensive System Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Architecture Deep Dive](#architecture-deep-dive)
3. [Service Details](#service-details)
4. [Database Interactions](#database-interactions)
5. [Elasticsearch Integration](#elasticsearch-integration)
6. [Data Flow Analysis](#data-flow-analysis)
7. [API Reference](#api-reference)
8. [Configuration Details](#configuration-details)
9. [Real-World Scenarios](#real-world-scenarios)
10. [Troubleshooting](#troubleshooting)

## System Overview

### Core Concept
The Multi-Source MFA Zero Trust Architecture Framework implements a comparative analysis between traditional MFA (baseline) and an advanced multi-signal validation approach (proposed framework). The system processes authentication requests through multiple validation layers, correlates threat intelligence, and makes dynamic trust decisions.

### Key Components
- **6 Microservices**: Validation, Trust, Gateway, SIEM, Metrics, Baseline
- **2 Data Stores**: PostgreSQL (structured data), Elasticsearch (document search/analytics)
- **1 Visualization**: Kibana (dashboards and analysis)
- **1 Simulator**: Enhanced traffic generator with STRIDE threat modeling

### Design Principles
- **Separation of Concerns**: Each service handles specific functionality
- **Event-Driven Architecture**: Services communicate via HTTP APIs and shared data stores
- **Polyglot Persistence**: SQL for transactions, NoSQL for analytics
- **Observability**: Comprehensive logging and metrics collection

## Architecture Deep Dive

### High-Level Flow
```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│   Raw       │───▶│  Validation  │───▶│    Trust    │───▶│   Gateway    │
│  Signals    │    │   Service    │    │   Service   │    │   Service    │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
                          │                    │                   │
                          ▼                    ▼                   ▼
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│  Baseline   │    │     SIEM     │    │  Metrics    │    │ PostgreSQL + │
│  Service    │    │   Service    │    │  Service    │    │Elasticsearch │
└─────────────┘    └──────────────┘    └─────────────┘    └──────────────┘
```

### Component Interaction Matrix
| Service | PostgreSQL | Elasticsearch | SIEM | Metrics | Gateway |
|---------|------------|---------------|------|---------|---------|
| Validation | ✓ (stores context) | ✓ (indexes signals) | - | - | Called by |
| Trust | ✓ (stores decisions) | - | Queries | - | Called by |
| Gateway | ✓ (stores MFA events) | ✓ (indexes decisions) | - | - | Orchestrates |
| SIEM | ✓ (stores alerts) | ✓ (queries & indexes) | - | Called by | Calls |
| Metrics | ✓ (reads all data) | - | - | - | Called by |
| Baseline | ✓ (stores decisions) | ✓ (indexes decisions) | - | - | Standalone |

## Service Details

### 1. Validation Service (Port 8001)
**Purpose**: Multi-signal validation and enrichment

**Core Functions**:
- **Signal Quality Assessment**: Evaluates completeness and accuracy of input signals
- **Geospatial Correlation**: Cross-validates GPS coordinates with WiFi BSSID locations
- **Device Fingerprinting**: Creates composite device identities from multiple attributes
- **TLS Analysis**: Validates certificate chains and detects anomalous patterns
- **Behavioral Analysis**: Identifies deviations from normal user patterns

**Key Endpoints**:
- `POST /validate`: Primary validation endpoint
- `GET /health`: Service health check
- `GET /stats`: Validation statistics

**Database Interactions**:
```sql
-- Stores validation results
INSERT INTO zta.validated_context (
    session_id, signals, quality, weights, reasons, method
) VALUES (?, ?, ?, ?, ?, ?);

-- Retrieves historical validation data for pattern analysis
SELECT * FROM zta.validated_context 
WHERE created_at > NOW() - INTERVAL '24 hours';
```

**Elasticsearch Interactions**:
```json
PUT /validated-context/_doc
{
  "@timestamp": "2024-01-01T00:00:00.000Z",
  "session_id": "sess-abc123",
  "signal_quality": 0.85,
  "validation_score": 0.92,
  "missing_signals": ["device_posture"],
  "anomalies_detected": ["gps_mismatch"]
}
```

### 2. Trust Service (Port 8002)
**Purpose**: Risk scoring and trust decision making

**Core Functions**:
- **Multi-Factor Risk Scoring**: Combines signal quality, threat intelligence, and behavioral analysis
- **STRIDE Threat Mapping**: Maps detected anomalies to STRIDE categories
- **Dynamic Threshold Adjustment**: Adapts decision thresholds based on confidence levels
- **Temporal Risk Analysis**: Considers time-based patterns in risk calculation

**Risk Calculation Algorithm**:
```python
def calculate_risk(signals, weights, siem_alerts):
    base_risk = TRUST_BASE_GAIN if weights else TRUST_FALLBACK_OBSERVED
    
    # Apply confidence weighting
    confidence_multiplier = min(sum(weights.values()) / VALIDATION_CONFIDENCE_THRESHOLD, 1.2)
    
    # STRIDE-based risk factors
    for reason in reasons:
        if reason in STRIDE_MAP:
            stride_name, bump = STRIDE_MAP[reason]
            adjusted_bump = bump * confidence_multiplier
            if is_benign_traffic:
                adjusted_bump *= 0.6
            risk += adjusted_bump
    
    # SIEM alert integration
    siem_risk = (siem_alerts['high'] * SIEM_HIGH_BUMP + 
                 siem_alerts['medium'] * SIEM_MED_BUMP) * confidence_multiplier
    
    return min(1.0, max(0.0, base_risk + risk + siem_risk))
```

**Database Interactions**:
```sql
-- Stores trust decisions with detailed metadata
INSERT INTO zta.trust_decisions (
    session_id, risk, decision, components
) VALUES (?, ?, ?, ?);

-- Components JSON structure:
{
  "reasons": ["GPS_MISMATCH", "TLS_ANOMALY"],
  "weights": {"gps": 0.8, "wifi": 0.9, "tls": 0.7},
  "siem_bump": {"high": 2, "medium": 1},
  "stride": ["Spoofing", "Tampering"],
  "decision_time_ms": 45,
  "confidence_multiplier": 1.1,
  "is_benign_traffic": false,
  "signal_quality": 0.85
}
```

### 3. Gateway Service (Port 8003)
**Purpose**: Request orchestration and final decision enforcement

**Core Functions**:
- **Service Orchestration**: Coordinates calls between validation, trust, and SIEM services
- **Decision Enforcement**: Translates risk scores into actionable MFA decisions
- **Session Management**: Tracks authentication sessions across the system
- **Audit Trail**: Maintains comprehensive logs of all decisions and actions

**Decision Logic**:
```python
def make_decision(risk_score):
    if risk_score >= DENY_THRESHOLD:    # 0.80
        return "deny", "DENY"
    elif risk_score >= ALLOW_THRESHOLD: # 0.12
        return "step_up", "MFA_REQUIRED"
    else:
        return "allow", "ALLOW"
```

**Database Interactions**:
```sql
-- Stores MFA events for audit trail
INSERT INTO zta.mfa_events (session_id, method, outcome, detail)
VALUES (?, 'gateway_policy', ?, ?);

-- Detail JSON structure:
{
  "risk": 0.45,
  "decision": "step_up",
  "enforcement": "MFA_REQUIRED",
  "reasons": ["UNKNOWN_DEVICE", "OUTSIDE_HOURS"],
  "stride": ["Spoofing"],
  "signals_used": ["gps", "wifi", "tls"],
  "siem_counts": {"high": 0, "medium": 1},
  "otp_demo": "123456"
}
```

**Elasticsearch Interactions**:
```json
PUT /mfa-events/_doc
{
  "@timestamp": "2024-01-01T00:00:00.000Z",
  "session_id": "sess-abc123",
  "risk": 0.45,
  "decision": "step_up",
  "enforcement": "MFA_REQUIRED",
  "reasons": ["UNKNOWN_DEVICE", "TLS_ANOMALY"],
  "siem_counts": {"high": 0, "medium": 1}
}

PUT /siem-alerts/_doc
{
  "@timestamp": "2024-01-01T00:00:00.000Z",
  "session_id": "sess-abc123",
  "risk": 0.75,
  "decision": "deny",
  "enforcement": "DENY",
  "reasons": ["DoS"]
}
```

### 4. SIEM Service (Port 8010)
**Purpose**: Security event correlation and threat intelligence

**Core Functions**:
- **Alert Aggregation**: Collects and correlates security events from multiple sources
- **STRIDE Classification**: Maps security events to STRIDE threat model categories
- **Temporal Correlation**: Identifies patterns across time windows
- **Threat Intelligence**: Integrates external threat feeds and indicators

**STRIDE Mapping**:
```python
STRIDE_MAP = {
    "SPOOFING": ("Spoofing", 0.15),
    "DOS": ("DoS", 0.35),
    "DDOS": ("DoS", 0.35),
    "POLICY_ELEVATION": ("EoP", 0.30),
    "DOWNLOAD_EXFIL": ("InformationDisclosure", 0.25),
    "TLS_ANOMALY": ("Tampering", 0.18),
    "POSTURE_OUTDATED": ("Tampering", 0.12),
    "REPUDIATION": ("Repudiation", 0.20)
}
```

**Database Interactions**:
```sql
-- Stores SIEM alerts with STRIDE classification
INSERT INTO zta.siem_alerts (session_id, stride, severity, source, raw)
VALUES (?, ?, ?, ?, ?);

-- Aggregates alerts for risk scoring
SELECT stride, severity, COUNT(*) as count
FROM zta.siem_alerts 
WHERE session_id = ? AND created_at > NOW() - INTERVAL '15 minutes'
GROUP BY stride, severity;
```

### 5. Metrics Service (Port 8030)
**Purpose**: Analytics and framework comparison

**Core Functions**:
- **Performance Metrics**: Response times, throughput, resource utilization
- **Security Metrics**: False positive rates, threat detection accuracy
- **Comparative Analysis**: Side-by-side framework performance comparison
- **Trend Analysis**: Historical pattern identification and forecasting

**Key Metrics Calculated**:
```python
def calculate_comparison_metrics():
    return {
        "proposed_framework": {
            "total_events": count_events("proposed"),
            "success_rate": calculate_success_rate("proposed"),
            "mfa_rate": calculate_mfa_rate("proposed"),
            "avg_risk_score": avg_risk("proposed"),
            "false_positive_rate": calc_fpr("proposed")
        },
        "baseline_framework": {
            "total_events": count_events("baseline"),
            "success_rate": calculate_success_rate("baseline"),
            "mfa_rate": calculate_mfa_rate("baseline"),
            "avg_risk_score": avg_risk("baseline"),
            "false_positive_rate": calc_fpr("baseline")
        }
    }
```

### 6. Baseline Service (Port 8020)
**Purpose**: Traditional MFA implementation for comparison

**Core Functions**:
- **Simple Risk Rules**: Traditional IP, time, and device-based rules
- **Basic Threat Detection**: Simple pattern matching for known threats
- **Device Trust Management**: Simple device fingerprinting and trust tracking
- **Decision Making**: Traditional threshold-based MFA triggering

**Risk Calculation (Fixed)**:
```python
def make_baseline_decision(signals):
    risk_score = 0.0
    factors = []
    
    # Suspicious IP check
    if is_suspicious_ip(signals.get("ip_geo", {}).get("ip")):
        factors.append("SUSPICIOUS_IP")
        risk_score += 0.25
    
    # Device trust check
    device_fingerprint = get_device_fingerprint(signals)
    if not is_trusted_device(device_fingerprint):
        factors.append("UNKNOWN_DEVICE")
        risk_score += 0.15
        
        # Only add time penalty for unknown devices
        if is_outside_business_hours():
            factors.append("OUTSIDE_HOURS")
            risk_score += 0.08
    
    # Threat detection
    threats = detect_simple_threats(signals)
    if threats:
        factors.extend(threats)
        risk_score += len(threats) * 0.20
    
    # Location anomaly (only for non-benign traffic)
    label = signals.get("label", "").upper()
    if label != "BENIGN":
        if has_location_mismatch(signals):
            factors.append("LOCATION_ANOMALY")
            risk_score += 0.10
    
    risk_score = min(1.0, max(0.0, risk_score))
    
    # Decision thresholds
    if risk_score >= 0.7:
        return "deny", "DENY"
    elif risk_score >= 0.25:
        return "step_up", "MFA_REQUIRED"
    else:
        return "allow", "ALLOW"
```

## Database Interactions

### Schema Overview
The PostgreSQL database uses the `zta` schema with the following key tables:

```sql
-- Core proposed framework tables
zta.validated_context      -- Signal validation results
zta.trust_decisions       -- Risk scoring and trust decisions  
zta.mfa_events           -- Final MFA decisions and outcomes
zta.siem_alerts          -- Security event correlation

-- Baseline framework tables
zta.baseline_decisions    -- Baseline MFA decisions
zta.baseline_auth_attempts -- Authentication outcomes
zta.baseline_trusted_devices -- Device trust tracking

-- Comparison and analysis tables
zta.framework_comparison  -- Side-by-side framework results
zta.security_classifications -- Threat detection accuracy
zta.performance_metrics  -- Timing and performance data
zta.metrics_cache       -- Computed metrics cache
```

### Transaction Patterns

**Proposed Framework Transaction**:
```sql
BEGIN;
-- 1. Store validation context
INSERT INTO zta.validated_context (...);

-- 2. Store trust decision  
INSERT INTO zta.trust_decisions (...);

-- 3. Store MFA event
INSERT INTO zta.mfa_events (...);

-- 4. Store SIEM alert (if risky)
INSERT INTO zta.siem_alerts (...);

-- 5. Store comparison data
INSERT INTO zta.framework_comparison (...);
COMMIT;
```

**Baseline Framework Transaction**:
```sql
BEGIN;
-- 1. Store baseline decision
INSERT INTO zta.baseline_decisions (...);

-- 2. Store auth attempt
INSERT INTO zta.baseline_auth_attempts (...);

-- 3. Update device trust (if successful)
INSERT INTO zta.baseline_trusted_devices (...) 
ON CONFLICT (device_fingerprint) DO UPDATE SET last_seen = NOW();

-- 4. Store comparison data
INSERT INTO zta.framework_comparison (...);
COMMIT;
```

### Query Patterns

**Risk Analysis Queries**:
```sql
-- Risk score distribution over time
SELECT 
    DATE_TRUNC('hour', created_at) as hour,
    AVG(risk) as avg_risk,
    MIN(risk) as min_risk,
    MAX(risk) as max_risk,
    COUNT(*) as decisions
FROM zta.trust_decisions 
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY DATE_TRUNC('hour', created_at)
ORDER BY hour;

-- Top threat patterns
SELECT 
    jsonb_array_elements_text(components->'reasons') as threat,
    COUNT(*) as frequency,
    AVG((components->>'confidence_multiplier')::float) as avg_confidence
FROM zta.trust_decisions 
WHERE created_at > NOW() - INTERVAL '7 days'
AND jsonb_array_length(components->'reasons') > 0
GROUP BY threat
ORDER BY frequency DESC;
```

**Comparative Analysis Queries**:
```sql
-- Framework performance comparison
SELECT 
    framework_type,
    COUNT(*) as total_decisions,
    COUNT(*) FILTER (WHERE decision = 'allow') as allow_count,
    COUNT(*) FILTER (WHERE decision = 'step_up') as stepup_count,
    COUNT(*) FILTER (WHERE decision = 'deny') as deny_count,
    AVG(risk_score) as avg_risk,
    AVG(processing_time_ms) as avg_processing_time
FROM zta.framework_comparison
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY framework_type;

-- Security accuracy analysis
SELECT 
    framework_type,
    COUNT(*) as total_classifications,
    COUNT(*) FILTER (WHERE false_positive = TRUE) as false_positives,
    COUNT(*) FILTER (WHERE false_negative = TRUE) as false_negatives,
    (COUNT(*) FILTER (WHERE false_positive = TRUE) * 100.0 / COUNT(*)) as fpr,
    (COUNT(*) FILTER (WHERE false_negative = TRUE) * 100.0 / COUNT(*)) as fnr
FROM zta.security_classifications
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY framework_type;
```

## Elasticsearch Integration

### Index Structure

**mfa-events Index**:
```json
{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "framework": {"type": "keyword"},
      "session_id": {"type": "keyword"},
      "risk": {"type": "float"},
      "decision": {"type": "keyword"},
      "enforcement": {"type": "keyword"},
      "factors": {"type": "keyword"},
      "processing_time_ms": {"type": "integer"}
    }
  }
}
```

**validated-context Index**:
```json
{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "session_id": {"type": "keyword"},
      "signal_quality": {"type": "float"},
      "validation_score": {"type": "float"},
      "missing_signals": {"type": "keyword"},
      "anomalies_detected": {"type": "keyword"},
      "gps_accuracy": {"type": "float"},
      "wifi_strength": {"type": "integer"}
    }
  }
}
```

**siem-alerts Index**:
```json
{
  "mappings": {
    "properties": {
      "@timestamp": {"type": "date"},
      "session_id": {"type": "keyword"},
      "stride_category": {"type": "keyword"},
      "severity": {"type": "keyword"},
      "risk": {"type": "float"},
      "source": {"type": "keyword"},
      "raw_event": {"type": "object"}
    }
  }
}
```

### Search and Aggregation Patterns

**Real-time Threat Monitoring**:
```json
GET /siem-alerts/_search
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-15m"}}},
        {"term": {"severity": "high"}}
      ]
    }
  },
  "aggs": {
    "by_stride": {
      "terms": {"field": "stride_category"},
      "aggs": {
        "avg_risk": {"avg": {"field": "risk"}},
        "sessions": {"cardinality": {"field": "session_id"}}
      }
    }
  }
}
```

**Framework Performance Analysis**:
```json
GET /mfa-events/_search
{
  "size": 0,
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "frameworks": {
      "terms": {"field": "framework"},
      "aggs": {
        "decisions": {
          "terms": {"field": "decision"}
        },
        "avg_risk": {
          "avg": {"field": "risk"}
        },
        "processing_time": {
          "stats": {"field": "processing_time_ms"}
        }
      }
    }
  }
}
```

## Data Flow Analysis

### End-to-End Request Processing

**Proposed Framework Flow**:
1. **Signal Collection**: Raw authentication signals received
2. **Validation** (`/validate`): 
   - Signal quality assessment
   - Geospatial correlation
   - Missing signal identification
   - Confidence weight calculation
3. **SIEM Query** (`/aggregate`):
   - Recent alert retrieval
   - Threat correlation
   - Risk factor identification
4. **Trust Scoring** (`/score`):
   - Multi-factor risk calculation
   - STRIDE threat mapping  
   - Confidence-weighted decision
5. **Gateway Orchestration** (`/decision`):
   - Service coordination
   - Final decision enforcement
   - Audit trail creation
6. **Data Persistence**:
   - PostgreSQL transaction
   - Elasticsearch indexing
   - Metrics cache update

**Baseline Framework Flow**:
1. **Signal Collection**: Raw authentication signals received
2. **Simple Analysis**:
   - IP reputation check
   - Time-based analysis
   - Device fingerprinting
   - Basic threat detection
3. **Decision Making**:
   - Rule-based risk scoring
   - Threshold comparison
   - MFA requirement determination
4. **Data Persistence**:
   - PostgreSQL transaction
   - Elasticsearch indexing
   - Device trust update

### Performance Characteristics

**Typical Response Times**:
- Validation Service: 15-30ms
- Trust Service: 20-40ms  
- Gateway Service: 45-80ms
- Baseline Service: 10-25ms
- SIEM Service: 5-15ms
- Metrics Service: 50-200ms

**Throughput Capacity**:
- Single instance: ~100-200 requests/second
- Horizontal scaling: Linear improvement
- Database bottleneck: ~1000 writes/second
- Elasticsearch: ~5000 documents/second

## API Reference

### Validation Service APIs

**POST /validate**
```json
Request:
{
  "signals": {
    "session_id": "sess-abc123",
    "auth": {
      "user": "john.doe",
      "method": "password",
      "timestamp": "2024-01-01T12:00:00Z"
    },
    "ip_geo": {
      "ip": "192.168.1.100",
      "country": "US",
      "city": "New York",
      "isp": "Verizon"
    },
    "gps": {
      "lat": 40.7128,
      "lon": -74.0060,
      "accuracy": 10,
      "timestamp": "2024-01-01T11:59:30Z"
    },
    "wifi_bssid": {
      "bssid": "00:11:22:33:44:55",
      "ssid": "CorporateWiFi",
      "signal_strength": -45
    },
    "tls": {
      "ja3": "769,47-53-5-10-49171-49172-49161-49162",
      "cipher": "TLS_AES_256_GCM_SHA384",
      "version": "1.3"
    },
    "device_posture": {
      "os": "Windows",
      "version": "10.0.19041",
      "patched": true,
      "antivirus": "enabled",
      "firewall": "enabled"
    },
    "user_behavior": {
      "typing_pattern": "normal",
      "mouse_movement": "consistent",
      "login_frequency": "regular"
    },
    "label": "BENIGN"
  }
}

Response:
{
  "session_id": "sess-abc123",
  "validated": {
    "vector": {
      "session_id": "sess-abc123",
      "auth": {...},
      "ip_geo": {...},
      // ... all validated signals
    },
    "weights": {
      "gps": 0.85,
      "wifi": 0.92,
      "tls": 0.78,
      "device": 0.88,
      "behavior": 0.76
    },
    "reasons": [],
    "method": "multi_signal_validation"
  },
  "quality": {
    "score": 0.84,
    "missing": [],
    "confidence": 0.89
  },
  "anomalies": [],
  "persistence": {"ok": true}
}
```

**GET /stats**
```json
Response:
{
  "validation_stats": {
    "total_validations": 15420,
    "avg_quality_score": 0.82,
    "avg_confidence": 0.87,
    "common_missing_signals": [
      {"signal": "device_posture", "frequency": 0.15},
      {"signal": "user_behavior", "frequency": 0.08}
    ]
  },
  "anomaly_detection": {
    "total_anomalies": 892,
    "top_anomalies": [
      {"type": "GPS_MISMATCH", "count": 245},
      {"type": "TLS_ANOMALY", "count": 178},
      {"type": "DEVICE_CHANGE", "count": 134}
    ]
  }
}
```

### Trust Service APIs

**POST /score**
```json
Request:
{
  "vector": {
    "session_id": "sess-abc123",
    // ... validated signals
  },
  "weights": {
    "gps": 0.85,
    "wifi": 0.92,
    "tls": 0.78
  },
  "reasons": ["GPS_MISMATCH"],
  "siem": {
    "high": 0,
    "medium": 1
  }
}

Response:
{
  "risk": 0.425,
  "decision": "step_up",
  "persistence": {"ok": true},
  "decision_time_ms": 34,
  "confidence_score": 0.85,
  "stride_components": ["Spoofing"]
}
```

### Gateway Service APIs

**POST /decision**
```json
Request:
{
  "validated": {
    "vector": {...},
    "weights": {...},
    "reasons": [...]
  },
  "siem": {"high": 0, "medium": 1}
}

Response:
{
  "session_id": "sess-abc123",
  "decision": "step_up",
  "enforcement": "MFA_STEP_UP",
  "risk": 0.45,
  "reasons": ["GPS_MISMATCH", "UNKNOWN_DEVICE"],
  "otp_demo": "123456",
  "persistence": {"ok": true}
}
```

### SIEM Service APIs

**GET /aggregate**
```json
Request: GET /aggregate?session_id=sess-abc123&minutes=15

Response:
{
  "session_id": "sess-abc123",
  "window_minutes": 15,
  "counts": {
    "high": 0,
    "medium": 2,
    "low": 5
  },
  "alerts": [
    {
      "stride": "Tampering",
      "severity": "medium",
      "timestamp": "2024-01-01T11:45:00Z",
      "source": "tls_monitor"
    }
  ]
}
```

### Metrics Service APIs

**GET /metrics/comparison**
```json
Response:
{
  "comparison_period_hours": 24,
  "proposed_framework": {
    "total_events": 2456,
    "decisions": {
      "allow": 1472,
      "step_up": 614,
      "deny": 370
    },
    "success_rate": 59.9,
    "mfa_rate": 25.0,
    "deny_rate": 15.1,
    "avg_risk_score": 0.342,
    "avg_processing_time_ms": 67.8,
    "security_accuracy": {
      "total_classifications": 2456,
      "false_positives": 147,
      "false_negatives": 89,
      "false_positive_rate": 5.98,
      "false_negative_rate": 3.62
    }
  },
  "baseline_framework": {
    "total_events": 2456,
    "decisions": {
      "allow": 1351,
      "step_up": 712,
      "deny": 393
    },
    "success_rate": 55.0,
    "mfa_rate": 29.0,
    "deny_rate": 16.0,
    "avg_risk_score": 0.389,
    "avg_processing_time_ms": 18.2,
    "security_accuracy": {
      "total_classifications": 2456,
      "false_positives": 234,
      "false_negatives": 156,
      "false_positive_rate": 9.53,
      "false_negative_rate": 6.35
    },
    "auth_outcomes": {
      "success": 1351,
      "mfa_required": 712,
      "failed": 393
    },
    "trusted_devices": 1247
  },
  "comparison": {
    "frameworks_available": ["proposed", "baseline"],
    "total_comparisons": 4912
  }
}
```

### Baseline Service APIs

**POST /decision**
```json
Request:
{
  "signals": {
    "session_id": "sess-abc123",
    "ip_geo": {"ip": "192.168.1.100"},
    "device_posture": {"patched": true},
    "label": "BENIGN"
  }
}

Response:
{
  "session_id": "sess-abc123",
  "decision": "allow",
  "enforcement": "ALLOW",
  "risk_score": 0.150,
  "factors": ["UNKNOWN_DEVICE"],
  "device_fingerprint": "win10-chrome-192.168.1.100",
  "decision_time_ms": 12,
  "persistence": {"ok": true}
}
```

## Configuration Details

### Environment Variables

**Database Configuration**:
```bash
DB_DSN="postgresql://user:password@localhost:5432/zta_framework"
PGOPTIONS="-c statement_timeout=30s"
```

**Elasticsearch Configuration**:
```bash
ES_HOST="http://elasticsearch:9200"
ES_USER="elastic"
ES_PASS="changeme"
ES_API_KEY=""  # Alternative to username/password
ES_MFA_INDEX="mfa-events"
ES_VALIDATED_INDEX="validated-context"
ES_INDEX="siem-alerts"
```

**Trust Service Thresholds**:
```bash
ALLOW_T=0.12           # Risk threshold for allowing access
DENY_T=0.80            # Risk threshold for denying access
SIEM_HIGH_BUMP=0.18    # Risk increase for high severity SIEM alerts
SIEM_MED_BUMP=0.08     # Risk increase for medium severity SIEM alerts
TRUST_BASE_GAIN=0.02   # Base risk with validated signals
TRUST_FALLBACK_OBSERVED=0.05  # Base risk without signals
VALIDATION_CONFIDENCE_THRESHOLD=0.70  # Minimum confidence for high-quality signals
BENIGN_TRAFFIC_PERCENT=70    # Expected percentage of benign traffic
```

**Baseline Service Configuration**:
```bash
BASELINE_SUSPICIOUS_IP_WEIGHT=0.25      # Risk weight for suspicious IPs
BASELINE_UNKNOWN_DEVICE_WEIGHT=0.15     # Risk weight for unknown devices
BASELINE_LOCATION_ANOMALY_WEIGHT=0.10   # Risk weight for location mismatches
BASELINE_OUTSIDE_HOURS_WEIGHT=0.08      # Risk weight for off-hours access
BASELINE_THREAT_WEIGHT=0.20             # Risk weight per detected threat
```

**SIEM Service Configuration**:
```bash
SEV_HIGH=0.7      # Risk threshold for high severity classification
SEV_MED=0.4       # Risk threshold for medium severity classification
```

**Security Configuration**:
```bash
TOTP_SECRET="JBSWY3DPEHPK3PXP"  # TOTP secret for MFA simulation
DIST_THRESHOLD_KM=100           # Distance threshold for GPS validation
```

### Docker Compose Configuration

**Service Dependencies**:
```yaml
validation:
  depends_on: [elasticsearch]
  
trust:
  depends_on: [validation]
  
gateway:
  depends_on: [validation, trust]
  
siem:
  depends_on: [elasticsearch, gateway]
  
metrics:
  depends_on: [elasticsearch, siem, gateway, trust, validation]
  
baseline:
  depends_on: [elasticsearch]
```

**Network Configuration**:
```yaml
networks:
  zta_net:
    driver: bridge
```

## Real-World Scenarios

### Scenario 1: Normal Business User Login

**Context**: A regular employee logging in during business hours from their office location.

**Input Signals**:
```json
{
  "session_id": "sess-normal-001",
  "auth": {
    "user": "alice.johnson@company.com",
    "method": "password",
    "timestamp": "2024-01-15T10:30:00Z"
  },
  "ip_geo": {
    "ip": "203.0.113.45",
    "country": "US",
    "city": "San Francisco",
    "isp": "Corporate ISP"
  },
  "gps": {
    "lat": 37.7749,
    "lon": -122.4194,
    "accuracy": 8
  },
  "wifi_bssid": {
    "bssid": "00:1A:2B:3C:4D:5E",
    "ssid": "Corporate_WiFi",
    "signal_strength": -35
  },
  "tls": {
    "ja3": "769,47-53-5-10-49171-49172",
    "cipher": "TLS_AES_256_GCM_SHA384"
  },
  "device_posture": {
    "os": "Windows",
    "version": "10.0.19041",
    "patched": true,
    "antivirus": "enabled"
  },
  "user_behavior": {
    "typing_pattern": "normal",
    "login_frequency": "regular"
  },
  "label": "BENIGN"
}
```

**Processing Flow**:

1. **Validation Service** (`POST /validate`):
   - GPS/WiFi correlation: ✓ Match (San Francisco office)
   - Signal quality: 0.92 (high)
   - Weights: `{"gps": 0.90, "wifi": 0.95, "tls": 0.88, "device": 0.92}`
   - Anomalies: None detected
   - Confidence: 0.91

2. **SIEM Service** (`GET /aggregate`):
   - Recent alerts: None
   - Risk factors: `{"high": 0, "medium": 0}`

3. **Trust Service** (`POST /score`):
   - Base risk: 0.02 (TRUST_BASE_GAIN)
   - Signal confidence multiplier: 1.0
   - STRIDE factors: None
   - Final risk: 0.02
   - Decision: "allow"

4. **Gateway Service** (`POST /decision`):
   - Enforcement: "ALLOW"
   - Processing time: 45ms
   - No MFA required

**Database Records**:
```sql
-- zta.validated_context
INSERT INTO zta.validated_context VALUES (
  'sess-normal-001', 
  '{"quality": 0.92, "confidence": 0.91}',
  '{"gps": 0.90, "wifi": 0.95, "tls": 0.88, "device": 0.92}',
  '[]'
);

-- zta.trust_decisions  
INSERT INTO zta.trust_decisions VALUES (
  'sess-normal-001',
  0.02,
  'allow',
  '{"confidence_multiplier": 1.0, "is_benign_traffic": true}'
);

-- zta.mfa_events
INSERT INTO zta.mfa_events VALUES (
  'sess-normal-001',
  'gateway_policy',
  'success',
  '{"risk": 0.02, "decision": "allow", "processing_time_ms": 45}'
);
```

**Elasticsearch Documents**:
```json
// mfa-events index
{
  "@timestamp": "2024-01-15T10:30:01.000Z",
  "framework": "proposed",
  "session_id": "sess-normal-001",
  "risk": 0.02,
  "decision": "allow",
  "enforcement": "ALLOW",
  "processing_time_ms": 45
}
```

**Baseline Comparison**:
- Baseline risk: 0.08 (unknown device penalty)
- Baseline decision: "allow" 
- Processing time: 12ms
- Both frameworks: ALLOW (✓ Correct decision)

### Scenario 2: Suspicious Login Attempt

**Context**: Login attempt from unusual location with device anomalies during off-hours.

**Input Signals**:
```json
{
  "session_id": "sess-suspicious-002",
  "auth": {
    "user": "alice.johnson@company.com",
    "method": "password",
    "timestamp": "2024-01-15T02:15:00Z"
  },
  "ip_geo": {
    "ip": "198.51.100.42",
    "country": "RO",
    "city": "Bucharest",
    "isp": "Unknown ISP"
  },
  "gps": {
    "lat": 44.4268,
    "lon": 26.1025,
    "accuracy": 50
  },
  "wifi_bssid": {
    "bssid": "AA:BB:CC:DD:EE:FF",
    "ssid": "FreeWiFi",
    "signal_strength": -70
  },
  "tls": {
    "ja3": "771,4865-4866-4867",
    "cipher": "TLS_CHACHA20_POLY1305"
  },
  "device_posture": {
    "os": "Linux",
    "version": "Ubuntu 20.04",
    "patched": false,
    "antivirus": "disabled"
  },
  "user_behavior": {
    "typing_pattern": "irregular",
    "login_frequency": "unusual"
  },
  "label": "Bot"
}
```

**Processing Flow**:

1. **Validation Service**:
   - GPS/WiFi correlation: ✗ Major mismatch (8000km apart)
   - Signal quality: 0.34 (low)
   - Weights: `{"gps": 0.25, "wifi": 0.30, "tls": 0.45, "device": 0.15}`
   - Anomalies: `["GPS_MISMATCH", "DEVICE_CHANGE", "TLS_ANOMALY"]`
   - Confidence: 0.29

2. **SIEM Service**:
   - Recent alerts: 3 medium severity (geographic anomaly, device change, behavior change)
   - Risk factors: `{"high": 0, "medium": 3}`

3. **Trust Service**:
   - Base risk: 0.05 (TRUST_FALLBACK_OBSERVED - low confidence)
   - STRIDE factors:
     - GPS_MISMATCH → Spoofing (0.15)
     - DEVICE_CHANGE → Tampering (0.12)  
     - TLS_ANOMALY → Tampering (0.18)
   - SIEM bump: 3 × 0.08 = 0.24
   - Confidence multiplier: 0.41 (low confidence reduces impact)
   - Final risk: 0.05 + (0.45 × 0.41) + 0.24 = 0.47
   - Decision: "step_up" (above 0.12 threshold)

4. **Gateway Service**:
   - Enforcement: "MFA_REQUIRED"
   - OTP generated: "847392"
   - Processing time: 78ms

**Database Records**:
```sql
-- zta.validated_context
INSERT INTO zta.validated_context VALUES (
  'sess-suspicious-002',
  '{"quality": 0.34, "confidence": 0.29}',
  '{"gps": 0.25, "wifi": 0.30, "tls": 0.45, "device": 0.15}',
  '["GPS_MISMATCH", "DEVICE_CHANGE", "TLS_ANOMALY"]'
);

-- zta.trust_decisions
INSERT INTO zta.trust_decisions VALUES (
  'sess-suspicious-002',
  0.47,
  'step_up',
  '{"stride": ["Spoofing", "Tampering"], "siem_bump": 0.24, "confidence_multiplier": 0.41}'
);

-- zta.siem_alerts
INSERT INTO zta.siem_alerts VALUES (
  'sess-suspicious-002',
  'Spoofing',
  'medium',
  'geographic_anomaly_detector',
  '{"distance_km": 8000, "usual_location": "San Francisco"}'
);
```

**Baseline Comparison**:
- Baseline factors: `["SUSPICIOUS_IP", "UNKNOWN_DEVICE", "OUTSIDE_HOURS", "LOCATION_ANOMALY", "NON_BENIGN_TRAFFIC"]`
- Baseline risk: 0.25 + 0.15 + 0.08 + 0.10 + 0.12 = 0.70
- Baseline decision: "deny" (above 0.70 threshold)
- Processing time: 8ms

**Framework Comparison**:
- Proposed: "step_up" (MFA challenge) - More nuanced response
- Baseline: "deny" (Block completely) - More conservative
- Proposed framework provides better user experience while maintaining security

### Scenario 3: Advanced Persistent Threat (APT)

**Context**: Sophisticated attacker using stolen credentials with advanced evasion techniques.

**Input Signals**:
```json
{
  "session_id": "sess-apt-003",
  "auth": {
    "user": "admin@company.com",
    "method": "password",
    "timestamp": "2024-01-15T14:22:00Z"
  },
  "ip_geo": {
    "ip": "203.0.113.100",
    "country": "US",
    "city": "San Francisco",
    "isp": "Corporate ISP"
  },
  "gps": {
    "lat": 37.7751,
    "lon": -122.4180,
    "accuracy": 5
  },
  "wifi_bssid": {
    "bssid": "00:1A:2B:3C:4D:5E",
    "ssid": "Corporate_WiFi",
    "signal_strength": -40
  },
  "tls": {
    "ja3": "769,47-53-5-10-49171-49172",
    "cipher": "TLS_AES_256_GCM_SHA384"
  },
  "device_posture": {
    "os": "Windows",
    "version": "10.0.19041",
    "patched": true,
    "antivirus": "enabled"
  },
  "user_behavior": {
    "typing_pattern": "slightly_irregular",
    "login_frequency": "elevated",
    "privileged_access": "attempting"
  },
  "label": "Web Attack"
}
```

**Processing Flow**:

1. **Validation Service**:
   - GPS/WiFi correlation: ✓ Match (appears legitimate)
   - Signal quality: 0.88 (high)
   - Weights: `{"gps": 0.92, "wifi": 0.90, "tls": 0.85, "device": 0.88}`
   - Anomalies: `["BEHAVIOR_ANOMALY"]` (subtle behavioral differences)
   - Confidence: 0.89

2. **SIEM Service**:
   - Recent alerts: 5 high severity (privilege escalation attempts, data exfiltration patterns)
   - Historical correlation: Multiple failed admin access attempts
   - Risk factors: `{"high": 5, "medium": 2}`

3. **Trust Service**:
   - Base risk: 0.02
   - STRIDE factors:
     - BEHAVIOR_ANOMALY → Repudiation (0.20)
     - POLICY_ELEVATION → Elevation of Privilege (0.30)
   - SIEM bump: (5 × 0.18) + (2 × 0.08) = 1.06 (capped at 0.90)
   - Confidence multiplier: 1.27 (high confidence amplifies concern)
   - Label penalty: 0.12 (Web Attack)
   - Final risk: 0.02 + (0.50 × 1.27) + 0.90 + 0.12 = 1.68 (capped at 1.0)
   - Decision: "deny"

4. **Gateway Service**:
   - Enforcement: "DENY"
   - Alert triggered to security team
   - Processing time: 92ms

**Database Records**:
```sql
-- zta.siem_alerts (multiple entries)
INSERT INTO zta.siem_alerts VALUES 
('sess-apt-003', 'EoP', 'high', 'privilege_monitor', '{"attempted_access": "admin_panel", "user_level": "standard"}'),
('sess-apt-003', 'InformationDisclosure', 'high', 'data_monitor', '{"query_pattern": "SELECT * FROM sensitive_table"}'),
('sess-apt-003', 'EoP', 'high', 'permission_monitor', '{"elevation_attempt": true, "target_resource": "user_database"}');

-- zta.trust_decisions
INSERT INTO zta.trust_decisions VALUES (
  'sess-apt-003',
  1.0,
  'deny',
  '{"stride": ["Repudiation", "EoP"], "siem_high": 5, "siem_medium": 2, "threat_level": "critical"}'
);

-- zta.security_classifications
INSERT INTO zta.security_classifications VALUES (
  'sess-apt-003',
  'Web Attack',
  '["BEHAVIOR_ANOMALY", "POLICY_ELEVATION"]',
  'proposed',
  false,  -- Not a false positive
  false   -- Not a false negative
);
```

**Baseline Comparison**:
- Baseline factors: `["NON_BENIGN_TRAFFIC"]`
- Baseline risk: 0.12 (minimal detection)
- Baseline decision: "allow" (fails to detect sophisticated threat)
- Processing time: 6ms

**Framework Comparison**:
- Proposed: "deny" (✓ Correct - blocks APT)
- Baseline: "allow" (✗ Incorrect - allows APT)
- Proposed framework's multi-signal correlation and SIEM integration successfully detects advanced threats

### Scenario 4: Mobile User Traveling

**Context**: Legitimate user traveling for business, accessing from airport WiFi.

**Input Signals**:
```json
{
  "session_id": "sess-travel-004",
  "auth": {
    "user": "bob.smith@company.com",
    "method": "password",
    "timestamp": "2024-01-15T18:45:00Z"
  },
  "ip_geo": {
    "ip": "198.51.100.25",
    "country": "UK",
    "city": "London",
    "isp": "Airport WiFi Provider"
  },
  "gps": {
    "lat": 51.4700,
    "lon": -0.4543,
    "accuracy": 20
  },
  "wifi_bssid": {
    "bssid": "11:22:33:44:55:66",
    "ssid": "Heathrow_Free_WiFi",
    "signal_strength": -60
  },
  "tls": {
    "ja3": "769,47-53-5-10-49171-49172",
    "cipher": "TLS_AES_256_GCM_SHA384"
  },
  "device_posture": {
    "os": "iOS",
    "version": "17.2",
    "patched": true,
    "mobile": true
  },
  "user_behavior": {
    "typing_pattern": "mobile_touch",
    "login_frequency": "travel_pattern"
  },
  "label": "BENIGN"
}
```

**Processing Flow**:

1. **Validation Service**:
   - GPS/WiFi correlation: ✓ Match (Heathrow Airport)
   - Travel pattern recognition: Business travel detected
   - Signal quality: 0.75 (good for mobile)
   - Weights: `{"gps": 0.78, "wifi": 0.72, "tls": 0.80, "device": 0.85}`
   - Anomalies: None (recognized travel pattern)
   - Confidence: 0.79

2. **SIEM Service**:
   - Recent alerts: 1 medium (geographic change)
   - Historical pattern: User has established travel history
   - Risk factors: `{"high": 0, "medium": 1}`

3. **Trust Service**:
   - Base risk: 0.02
   - Geographic change recognized as legitimate travel
   - Travel context reduces location-based penalties
   - SIEM bump: 1 × 0.08 = 0.08
   - Confidence multiplier: 1.13
   - Final risk: 0.02 + 0.08 = 0.10
   - Decision: "allow" (below 0.12 threshold)

4. **Gateway Service**:
   - Enforcement: "ALLOW"
   - Travel alert logged for security team awareness
   - Processing time: 52ms

**Baseline Comparison**:
- Baseline factors: `["UNKNOWN_DEVICE", "LOCATION_ANOMALY"]`
- Baseline risk: 0.15 + 0.10 = 0.25
- Baseline decision: "step_up"
- Processing time: 10ms

**Framework Comparison**:
- Proposed: "allow" (Recognizes legitimate travel)
- Baseline: "step_up" (Conservative approach to location change)
- Proposed framework's contextual analysis provides better user experience for legitimate travel

### Scenario 5: DDoS Attack Pattern

**Context**: Coordinated DDoS attack with multiple compromised endpoints.

**Input Signals** (one of many similar requests):
```json
{
  "session_id": "sess-ddos-005",
  "auth": {
    "user": "service.account@company.com",
    "method": "api_key",
    "timestamp": "2024-01-15T16:30:15Z"
  },
  "ip_geo": {
    "ip": "203.0.113.200",
    "country": "CN",
    "city": "Beijing",
    "isp": "Botnet Infrastructure"
  },
  "gps": null,
  "wifi_bssid": null,
  "tls": {
    "ja3": "771,4865-4866-4867",
    "cipher": "unusual_cipher"
  },
  "device_posture": null,
  "user_behavior": {
    "request_rate": "extremely_high",
    "pattern": "automated"
  },
  "label": "DDoS"
}
```

**Processing Flow**:

1. **Validation Service**:
   - Signal quality: 0.20 (many missing signals)
   - High automation detected
   - Weights: `{"tls": 0.30}` (only TLS available)
   - Anomalies: `["HIGH_FREQUENCY", "AUTOMATION", "MISSING_SIGNALS"]`
   - Confidence: 0.15

2. **SIEM Service**:
   - Recent alerts: 50+ high severity (DDoS pattern detected)
   - Rate limiting triggered
   - Coordinated attack signatures detected
   - Risk factors: `{"high": 50, "medium": 20}` (capped)

3. **Trust Service**:
   - Base risk: 0.05 (low confidence fallback)
   - STRIDE factors:
     - HIGH_FREQUENCY → Denial of Service (0.35)
     - AUTOMATION → Tampering (0.18)
   - SIEM bump: 0.90 (maximum)
   - Confidence multiplier: 0.21 (very low)
   - Label penalty: 0.35 (DDoS)
   - Final risk: 0.05 + (0.53 × 0.21) + 0.90 + 0.35 = 1.41 (capped at 1.0)
   - Decision: "deny"

4. **Gateway Service**:
   - Enforcement: "DENY"
   - IP blacklisting triggered
   - DDoS mitigation activated
   - Processing time: 15ms (fast rejection)

**Database Records**:
```sql
-- zta.siem_alerts (pattern of similar entries)
INSERT INTO zta.siem_alerts VALUES 
('sess-ddos-005', 'DoS', 'high', 'rate_limiter', '{"requests_per_second": 500, "threshold": 10}'),
('sess-ddos-005', 'DoS', 'high', 'pattern_detector', '{"attack_signature": "syn_flood", "confidence": 0.95}');

-- zta.security_classifications
INSERT INTO zta.security_classifications VALUES (
  'sess-ddos-005',
  'DDoS',
  '["HIGH_FREQUENCY", "AUTOMATION"]',
  'proposed',
  false,  -- Correct positive detection
  false   -- Not a false negative
);
```

**Baseline Comparison**:
- Baseline factors: `["SUSPICIOUS_IP", "UNKNOWN_DEVICE", "NON_BENIGN_TRAFFIC"]`
- Baseline risk: 0.25 + 0.15 + 0.12 = 0.52
- Baseline decision: "deny" (correct but slower detection)
- Processing time: 8ms

**Framework Comparison**:
- Proposed: "deny" (✓ Fast, accurate detection with context)
- Baseline: "deny" (✓ Correct but less sophisticated detection)
- Both frameworks block the attack, but proposed provides richer forensics and faster automated response

### Performance Analysis Summary

**Average Response Times by Scenario**:
| Scenario | Proposed Framework | Baseline Framework | Difference |
|----------|-------------------|-------------------|------------|
| Normal User | 45ms | 12ms | +33ms |
| Suspicious Login | 78ms | 8ms | +70ms |
| APT Attack | 92ms | 6ms | +86ms |
| Traveling User | 52ms | 10ms | +42ms |
| DDoS Attack | 15ms | 8ms | +7ms |

**Decision Accuracy**:
| Scenario | Proposed Accuracy | Baseline Accuracy | Improvement |
|----------|------------------|------------------|-------------|
| Normal User | ✓ Correct (Allow) | ✓ Correct (Allow) | Same |
| Suspicious Login | ✓ Better (Step-up) | ⚠ Conservative (Deny) | Better UX |
| APT Attack | ✓ Correct (Deny) | ✗ Missed (Allow) | Critical |
| Traveling User | ✓ Better (Allow) | ⚠ Conservative (Step-up) | Better UX |
| DDoS Attack | ✓ Correct (Deny) | ✓ Correct (Deny) | Same |

## Troubleshooting

### Common Issues and Solutions

**1. Database Connection Failures**
```
Symptoms: Services showing "Database connection unavailable"
Diagnosis: Check DB_DSN environment variable and database accessibility
Solutions:
- Verify PostgreSQL is running: `docker ps | grep postgres`
- Test connection: `pg_isready -h localhost -p 5432`
- Check DSN format: `postgresql://user:pass@host:port/database`
```

**2. Elasticsearch Indexing Failures**
```
Symptoms: No data appearing in Kibana, ES_INDEX errors in logs
Diagnosis: Elasticsearch connectivity or authentication issues
Solutions:
- Check ES health: `curl http://localhost:9200/_cluster/health`
- Verify credentials: `curl -u elastic:changeme http://localhost:9200/`
- Recreate indices: `curl -X DELETE http://localhost:9200/mfa-events`
```

**3. Risk Scores Always Maximum/Minimum**
```
Symptoms: All decisions showing risk = 1.0 or risk = 0.0
Diagnosis: Threshold configuration or signal quality issues
Solutions:
- Check environment variables: ALLOW_T, DENY_T values
- Verify signal quality in validation service
- Review SIEM alert volumes: may be overwhelming risk calculation
```

**4. Services Not Communicating**
```
Symptoms: HTTP timeouts, "Service unavailable" errors
Diagnosis: Network connectivity or service startup order
Solutions:
- Check service health: `curl http://localhost:800X/health`
- Verify Docker network: `docker network ls`
- Check service dependencies in docker-compose.yml
```

**5. Performance Degradation**
```
Symptoms: Slow response times, timeouts
Diagnosis: Resource constraints or database performance
Solutions:
- Monitor resource usage: `docker stats`
- Check database connections: Look for connection pool exhaustion
- Review Elasticsearch heap: May need memory increase
- Optimize queries: Add database indexes if needed
```

This comprehensive documentation provides complete technical details of the Multi-Source MFA Zero Trust Architecture Framework, including all service interactions, database schemas, API specifications, and real-world scenarios demonstrating both frameworks' capabilities.