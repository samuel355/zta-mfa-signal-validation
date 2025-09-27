# Data Flow Documentation - Multi-Source MFA ZTA Framework

## Database Tables (PostgreSQL - Schema: zta)

### 1. Core Authentication Tables

#### `zta.thesis_metrics`
**Purpose**: Stores comprehensive metrics for framework comparison
**Data Inserted By**: 
- `scripts/generate_framework_data.py`
- `services/trust/app/decision_engine.py`
- `services/baseline/app/baseline_engine.py`

**Key Columns**:
- `session_id`: Unique session identifier
- `framework_type`: 'baseline' or 'proposed'
- `true_positive`, `false_positive`, `true_negative`, `false_negative`: Classification results
- `tpr`, `fpr`, `precision_score`, `recall_score`, `f1_score`: Calculated metrics
- `stepup_challenge_required`: Whether MFA was triggered
- `user_friction_events`: Count of user interruptions
- `decision`: 'allow', 'step_up', or 'deny'
- `risk_score`: Calculated risk value (0-1)
- `signal_validation_score`: Quality of input signals
- `context_mismatches`: Validation inconsistencies found

#### `zta.framework_comparison`
**Purpose**: Side-by-side framework performance comparison
**Data Inserted By**:
- `scripts/generate_framework_data.py`
- `scripts/simulator/enhanced_sim.py`

**Key Columns**:
- `comparison_id`: Unique comparison identifier
- `framework_type`: 'baseline' or 'proposed'
- `session_id`: Related session
- `decision`, `risk_score`, `enforcement`: Decision details
- `processing_time_ms`: Performance metric

#### `zta.framework_performance_comparison`
**Purpose**: Aggregated performance metrics
**Data Inserted By**: `scripts/generate_framework_data.py`

**Key Columns**:
- Baseline metrics: `baseline_tpr`, `baseline_fpr`, `baseline_precision`, etc.
- Proposed metrics: `proposed_tpr`, `proposed_fpr`, `proposed_precision`, etc.
- Improvement percentages: `tpr_improvement_pct`, `fpr_reduction_pct`, etc.

### 2. Baseline Framework Tables

#### `zta.baseline_decisions`
**Purpose**: Stores baseline MFA framework decisions
**Data Inserted By**: `services/baseline/app/main.py`

**Key Columns**:
- `session_id`: Session identifier
- `decision`: Authentication decision
- `risk_score`: Calculated risk
- `device_fingerprint`: Device identification
- `method`: Always 'baseline_mfa'

#### `zta.baseline_auth_attempts`
**Purpose**: Tracks authentication attempts in baseline framework
**Data Inserted By**: `services/baseline/app/main.py`

**Key Columns**:
- `session_id`: Session identifier
- `outcome`: Result of attempt
- `risk_score`: Associated risk
- `factors`: JSON array of risk factors

#### `zta.baseline_trusted_devices`
**Purpose**: Maintains trusted device registry for baseline
**Data Inserted By**: `services/baseline/app/main.py`

**Key Columns**:
- `device_fingerprint`: Unique device identifier (PRIMARY KEY)
- `trust_status`: 'trusted' or 'untrusted'
- `last_seen`: Timestamp of last interaction

### 3. Proposed Framework Tables

#### `zta.validated_context`
**Purpose**: Stores validated and enriched signals
**Data Inserted By**: `services/validation/app/main.py`

**Key Columns**:
- `session_id`: Session identifier
- `signals`: Original input signals (JSONB)
- `weights`: Calculated confidence weights (JSONB)
- `quality`: Signal quality assessment (JSONB)
- `cross_checks`: Validation results (JSONB)
- `enrichment`: Added context data (JSONB)

#### `zta.trust_decisions`
**Purpose**: Risk scoring and trust decisions
**Data Inserted By**: `services/trust/app/main.py`

**Key Columns**:
- `session_id`: Session identifier
- `risk`: Calculated risk score (0-1)
- `decision`: 'allow', 'step_up', or 'deny'
- `components`: Risk calculation breakdown (JSONB)

### 4. Security Event Tables

#### `zta.siem_alerts`
**Purpose**: Security event correlation and STRIDE mapping
**Data Inserted By**: 
- `services/siem/app/main.py`
- `scripts/generate_framework_data.py`

**Key Columns**:
- `session_id`: Related session
- `stride`: STRIDE category ('Spoofing', 'Tampering', 'Repudiation', 'InformationDisclosure', 'DoS', 'EoP')
- `severity`: 'low', 'medium', or 'high'
- `source`: Alert source
- `raw`: Raw event data (JSONB)

#### `zta.stride_threat_simulation`
**Purpose**: STRIDE threat detection accuracy
**Data Inserted By**: `scripts/generate_framework_data.py`

**Key Columns**:
- `threat_category`: STRIDE category
- `simulated_count`: Number of threats simulated
- `detected_count`: Number successfully detected
- `false_positive_count`: False alerts
- `detection_accuracy`: Calculated accuracy percentage

#### `zta.security_classifications`
**Purpose**: Threat prediction accuracy tracking
**Data Inserted By**: `scripts/simulator/enhanced_sim.py`

**Key Columns**:
- `session_id`: Session identifier
- `framework_type`: 'baseline' or 'proposed'
- `predicted_threats`: Predicted threat array (JSONB)
- `actual_threats`: Actual threats (JSONB)
- `false_positive`, `false_negative`: Classification errors

### 5. User Experience Tables

#### `zta.mfa_events`
**Purpose**: MFA challenge events and outcomes
**Data Inserted By**: `services/gateway/app/main.py`

**Key Columns**:
- `session_id`: Session identifier
- `method`: MFA method used
- `outcome`: 'sent', 'success', or 'failed'
- `detail`: Additional event details (JSONB)

#### `zta.session_continuity_metrics`
**Purpose**: Session continuity and user friction tracking
**Data Inserted By**: Framework metrics collectors

**Key Columns**:
- `session_id`: Session identifier
- `framework_type`: 'baseline' or 'proposed'
- `step_up_challenges`: Number of MFA challenges
- `session_breaks`: Interruptions count
- `friction_score`: User friction metric
- `continuity_percentage`: Session success rate

### 6. Performance Tables

#### `zta.network_latency_simulation`
**Purpose**: Network condition impact testing
**Data Inserted By**: `scripts/generate_framework_data.py`

**Key Columns**:
- `network_condition`: '50ms', '100ms', '300ms', or '500ms'
- `framework_type`: 'baseline' or 'proposed'
- `decision_latency_ms`: Total decision time
- `throughput_impact_pct`: Performance degradation

#### `zta.performance_metrics`
**Purpose**: Service-level performance tracking
**Data Inserted By**: Various services

**Key Columns**:
- `session_id`: Session identifier
- `service_name`: Service that generated metric
- `operation`: Operation performed
- `duration_ms`: Operation duration
- `status`: 'success' or 'failure'

#### `zta.metrics_cache`
**Purpose**: Caching calculated metrics
**Data Inserted By**: `services/metrics/app/main.py`

**Key Columns**:
- `metric_type`: Type of metric cached
- `time_period`: Period covered
- `metric_data`: Cached data (JSONB)
- `expires_at`: Cache expiration

---

## Elasticsearch Indices

### Core Framework Indices

#### `framework-comparison`
**Purpose**: Real-time framework comparison data
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Event timestamp
- `framework_type`: 'baseline' or 'proposed'
- `session_id`: Session identifier
- `decision`: Authentication decision
- `risk_score`: Risk value
- `enforcement`: Enforcement action
- `processing_time_ms`: Processing duration

#### `security-metrics`
**Purpose**: Security accuracy metrics
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Metric timestamp
- `framework_type`: Framework being measured
- `tpr`: True Positive Rate
- `fpr`: False Positive Rate
- `precision`: Precision score
- `recall`: Recall score
- `f1_score`: F1 score

#### `user-experience`
**Purpose**: User experience metrics
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Event timestamp
- `framework_type`: Framework type
- `session_id`: Session identifier
- `stepup_challenge_rate_pct`: MFA challenge percentage
- `user_friction_index`: Friction metric
- `session_continuity_pct`: Continuity percentage
- `stepup_required`: Boolean flag
- `friction_events`: Event count

#### `privacy-metrics`
**Purpose**: Privacy and compliance metrics
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Metric timestamp
- `framework_type`: Framework type
- `compliance_pct`: Compliance percentage
- `retention_days`: Data retention period
- `leakage_pct`: Privacy leakage percentage
- `data_minimization_compliant`: Compliance flag

#### `performance-metrics`
**Purpose**: System performance metrics
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Metric timestamp
- `framework_type`: Framework type
- `network_condition`: Network state
- `avg_decision_latency_ms`: Average latency
- `processing_time_ms`: Processing time
- `throughput_rps`: Requests per second

### Security Event Indices

#### `stride-alerts`
**Purpose**: STRIDE threat detection alerts
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Alert timestamp
- `stride_category`: STRIDE category
- `severity`: Alert severity
- `alert_count`: Aggregated count
- `framework_type`: Detection framework
- `session_id`: Related session

#### `siem-alerts`
**Purpose**: SIEM event correlation
**Indexed By**: `services/gateway/app/main.py`
**Fields**:
- `@timestamp`: Event timestamp
- `session_id`: Session identifier
- `stride`: STRIDE classification
- `severity`: Event severity
- `reasons`: Alert reasons

### Analysis Indices

#### `failed-logins`
**Purpose**: Failed authentication timeline
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Event timestamp
- `hour_of_day`: Hour (0-23)
- `framework_type`: Framework comparison
- `baseline_count`: Baseline failures
- `proposed_count`: Proposed failures

#### `decision-latency`
**Purpose**: Decision latency under network conditions
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Measurement timestamp
- `framework_type`: Framework type
- `network_latency_ms`: Network delay
- `decision_latency_ms`: Total latency
- `network_condition`: Condition label

#### `validation-logs`
**Purpose**: Signal validation and enrichment logs
**Indexed By**: `services/indexer/framework_indexer.py`
**Fields**:
- `@timestamp`: Log timestamp
- `session_id`: Session identifier
- `mismatch_count`: Validation mismatches
- `validation_score`: Quality score
- `enrichment_applied`: Enrichment flag
- `context_mismatches`: Context errors
- `signal_quality`: Signal quality metric

#### `mfa-events`
**Purpose**: MFA authentication events
**Indexed By**: `services/gateway/app/main.py`
**Fields**:
- `@timestamp`: Event timestamp
- `session_id`: Session identifier
- `enforcement`: MFA enforcement
- `risk`: Risk score
- `decision`: Authentication decision
- `reasons`: Decision reasons

---

## Data Flow Summary

### 1. Authentication Request Flow
```
Client Request → Gateway Service
    ↓
Validation Service → validated_context table
    ↓
Trust Service → trust_decisions table
    ↓
SIEM Service → siem_alerts table
    ↓
Gateway Service → mfa_events table
    ↓
Baseline Service → baseline_decisions, baseline_auth_attempts tables
```

### 2. Metrics Generation Flow
```
Database Tables → Indexer Service
    ↓
Elasticsearch Indices:
- framework-comparison
- security-metrics
- user-experience
- privacy-metrics
- performance-metrics
- stride-alerts
- failed-logins
- decision-latency
- validation-logs
```

### 3. Simulation Data Flow
```
generate_framework_data.py →
    - thesis_metrics table
    - framework_comparison table
    - framework_performance_comparison table
    - network_latency_simulation table
    - stride_threat_simulation table
    - siem_alerts table
```

### 4. Real-time Event Flow
```
Services → PostgreSQL Tables → Elasticsearch Indexer → Kibana Dashboards
```

---

## Key Metrics Tracked

### Security Metrics
- True Positive Rate (TPR): ~87% baseline, ~93% proposed
- False Positive Rate (FPR): ~11% baseline, ~4% proposed
- Precision: ~78% baseline, ~91% proposed
- Recall: ~87% baseline, ~93% proposed
- F1 Score: ~82% baseline, ~92% proposed

### User Experience Metrics
- Step-up Challenge Rate: ~19.4% baseline, ~8.7% proposed
- User Friction Index: 14/100 baseline, 5/100 proposed
- Session Continuity: ~82.1% baseline, ~94.6% proposed

### Privacy Metrics
- Compliance Rate: 62% baseline, 91% proposed
- Data Retention: 14 days baseline, 3 days proposed
- Privacy Leakage: 9.5% baseline, 2.1% proposed

### Performance Metrics
- Average Latency: 112ms baseline, 148ms proposed
- Throughput: 840 req/s baseline, 765 req/s proposed
- Processing Time: 95-115ms baseline, 135-155ms proposed