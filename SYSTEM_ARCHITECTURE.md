# Multi-Source MFA ZTA Framework - System Architecture & Flow

## 📋 Table of Contents

1. System Overview
2. Architecture Components
3. Proposed Framework Flow
4. Baseline Framework Flow
5. Data Sources & Datasets
6. Database Schema
7. Service Interactions
8. Simulation & Evaluation
9. File Structure
10. Deployment & Operations

## 🏗️ System Overview

The Multi-Source MFA ZTA Framework is a research platform that compares two authentication approaches:

- **Proposed Framework**: Advanced Zero Trust Architecture with multi-source validation
- **Baseline Framework**: Traditional MFA system for comparison

Both frameworks process the same input signals and store results for comparative analysis.

## 🧩 Architecture Components

### Core Services Architecture


┌─────────────────────────────────────────────────────────────┐
│                    ENHANCED SIMULATOR                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌────────┐ │
│  │   CICIDS    │ │    WiFi     │ │   Device    │ │  TLS   │ │
│  │  (Network)  │ │ (Location)  │ │ (Posture)   │ │ (Cert) │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └────────┘ │
└─────────────────────────┬───────────────────────────────────┘
                          │ Generates Signals with STRIDE
                          ▼
    ┌─────────────────────────────────────────────────────────┐
    │                DUAL FRAMEWORK PROCESSING                │
    └─────────────────────┬───────────────────────────────────┘
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
┌─────────────────────────┐  ┌─────────────────────────┐
│   PROPOSED FRAMEWORK    │  │   BASELINE FRAMEWORK    │
│                         │  │                         │
│ ┌─────────────────────┐ │  │ ┌─────────────────────┐ │
│ │   VALIDATION        │ │  │ │   BASELINE SERVICE  │ │
│ │   (Enrichment)      │ │  │ │   (Simple Rules)    │ │
│ └─────────┬───────────┘ │  │ └─────────┬───────────┘ │
│           ▼             │  │           ▼             │
│ ┌─────────────────────┐ │  │ ┌─────────────────────┐ │
│ │   TRUST ENGINE      │ │  │ │   DIRECT DECISION   │ │
│ │   (Risk Scoring)    │ │  │ │                     │ │
│ └─────────┬───────────┘ │  │ └─────────┬───────────┘ │
│           ▼             │  │           ▼             │
│ ┌─────────────────────┐ │  │ ┌─────────────────────┐ │
│ │   GATEWAY           │ │  │ │   DATABASE STORAGE  │ │
│ │   (Final Decision)  │ │  │ │                     │ │
│ └─────────┬───────────┘ │  │ └─────────────────────┘ │
└───────────┼─────────────┘  └─────────────────────────┘
            ▼
┌─────────────────────────────────────────────────────────────┐
│                    DATABASE (SUPABASE)                      │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────────────────┐│
│  │  Framework  │ │  Baseline   │ │  Performance Metrics    ││
│  │ Comparison  │ │ Decisions   │ │  Security Classifications│
│  └─────────────┘ └─────────────┘ └─────────────────────────┘│
└─────────────────────────────────────────────────────────────┘


## 🔄 Proposed Framework Flow

### Step 1: Signal Generation
**File:** `scripts/simulator/enhanced_sim.py`

Input Data Sources → Enhanced Simulator
├── /data/cicids/*.csv (Network traffic patterns)
├── /data/wifi/wigle_sample.csv (WiFi access points & GPS)
├── /data/device_posture/device_posture.csv (Device security status)
└── /data/tls/ja3_fingerprints.csv (TLS fingerprints)


### Step 2: STRIDE Classification
**Logic in:** `enhanced_sim.py` - `_apply_stride_scenario()`

Signal → STRIDE Bucket Assignment:
├── Spoofing (20%): GPS offset from WiFi location
├── Tampering (15%): Bad TLS fingerprints → HEARTBLEED label
├── Repudiation (15%): BENIGN with repudiation flag
├── Information Disclosure (15%): → INFILTRATION label
├── Denial of Service (20%): → DDOS label
└── Elevation of Privilege (15%): → WEB ATTACK label


### Step 3: Validation Service
**File:** `services/validation/app/main.py`
**Endpoint:** `POST /validate`


Raw Signal → Validation Service:
├── Enrichment (`app/enrichment.py`):
│   ├── IP Geolocation (GeoLite2)
│   ├── WiFi Location Mapping
│   ├── TLS Fingerprint Analysis
│   └── Device Security Lookup
├── Cross-validation:
│   ├── GPS vs WiFi location distance
│   ├── Signal consistency checks
│   └── Data quality validation
└── Output: Validated signal with enriched data


### Step 4: Trust Engine
**File:** `services/trust/app/main.py`
**Endpoint:** `POST /score`


Validated Signal → Trust Engine:
├── Risk Scoring Algorithm:
│   ├── Base trust score calculation
│   ├── SIEM alert integration
│   ├── Historical behavior analysis
│   └── Multi-factor weight adjustment
└── Output: Risk score (0.0 - 1.0)


### Step 5: Gateway Decision
**File:** `services/gateway/app/main.py`
**Endpoint:** `POST /decision`


Trust Score + Validated Data → Gateway:
├── Decision Logic:
│   ├── Risk thresholds evaluation
│   ├── Policy enforcement rules
│   ├── MFA requirements assessment
│   └── Final access decision
└── Output: {decision, enforcement, risk_score, reasons}


### Step 6: SIEM Integration
**File:** `services/siem/app/main.py`
**Background Process:** Elasticsearch polling


Elasticsearch Events → SIEM Service:
├── Event Classification:
│   ├── Threat detection patterns
│   ├── STRIDE category mapping
│   ├── Severity assessment (HIGH/MEDIUM/LOW)
│   └── Alert generation
└── Output: Security alerts to Trust Engine


## ⚖️ Baseline Framework Flow

### Step 1: Signal Reception
**File:** `services/baseline/app/main.py`
**Endpoint:** `POST /decision`


Raw Signal → Baseline Service:
└── Simple MFA Logic (Traditional approach)


### Step 2: Basic Risk Assessment
**Logic in:** `baseline/app/main.py` - `make_baseline_decision()`


Signal Analysis:
├── IP Reputation Check:
│   ├── Suspicious IP ranges (10.0.0.*, 192.168.*, etc.)
│   └── Risk Score: +0.3
├── Time-based Analysis:
│   ├── Outside business hours (8 AM - 6 PM)
│   ├── Weekend access
│   └── Risk Score: +0.2
├── Device Recognition:
│   ├── Unknown device fingerprint
│   ├── Trust history lookup
│   └── Risk Score: +0.2
├── Failed Attempts:
│   ├── Recent authentication failures
│   ├── Brute force detection
│   └── Risk Score: +0.4
└── Simple Threat Detection:
    ├── CICIDS label-based detection
    ├── DOS/Web Attack patterns
    └── Risk Score: +0.15 per threat


### Step 3: Decision Logic

Total Risk Score → Decision:
├── Risk >= 0.7: DENY access
├── Risk >= 0.3: STEP_UP (MFA required)
└── Risk < 0.3: ALLOW access


### Step 4: Database Storage

Decision Data → Supabase Tables:
├── zta.baseline_decisions
├── zta.baseline_auth_attempts
└── zta.baseline_trusted_devices


## 📊 Data Sources & Datasets

### Primary Datasets

#### 1. CICIDS Network Traffic
**Location:** `/data/cicids/`

Files:
├── Monday-WorkingHours.pcap_ISCX.csv
├── Tuesday-WorkingHours.pcap_ISCX.csv
├── Wednesday-workingHours.pcap_ISCX.csv
├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
├── Friday-WorkingHours-Morning.pcap_ISCX.csv
├── Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv
└── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

Content: Network flow features, attack labels (BENIGN, DDOS, Web Attack, etc.)
Usage: Ground truth for security classification


#### 2. WiFi Access Points
**Location:** `/data/wifi/wigle_sample.csv`

Schema:
├── bssid: WiFi access point identifier
├── lat: Latitude coordinates
└── lon: Longitude coordinates

Usage: Location validation, GPS-WiFi consistency checks


#### 3. Device Posture
**Location:** `/data/device_posture/device_posture.csv`

Schema:
├── device_id: Unique device identifier
├── os: Operating system
├── patched: Security patch status
├── edr: Endpoint detection status
└── last_update: Last security update

Usage: Device trust assessment


#### 4. TLS Fingerprints
**Location:** `/data/tls/ja3_fingerprints.csv`

Schema:
├── ja3: TLS fingerprint hash
└── tag: Classification (normal, malware, tor_suspect, etc.)

Usage: TLS traffic analysis, malware detection


#### 5. GeoIP Database
**Location:** `/data/geolite2/GeoLite2-City.mmdb`

Content: IP address to geographic location mapping
Usage: IP geolocation enrichment


## 🗄️ Database Schema

### ZTA Schema Tables (`zta.*`)

#### Framework Comparison
sql
zta.framework_comparison:
├── comparison_id: Batch identifier
├── framework_type: 'proposed' | 'baseline'
├── session_id: Request identifier
├── decision: 'allow' | 'step_up' | 'deny'
├── risk_score: 0.0 - 1.0
├── enforcement: Action taken
├── factors: Decision reasoning (JSONB)
├── processing_time_ms: Performance metric
└── created_at: Timestamp


#### Baseline Framework Tables
sql
zta.baseline_decisions:
├── session_id, decision, risk_score
├── factors: Risk factors identified
├── device_fingerprint: Device identifier
├── original_signals: Input data
└── method: 'baseline_mfa'

zta.baseline_auth_attempts:
├── session_id, outcome: 'success' | 'failed' | 'mfa_required'
├── risk_score, factors
└── created_at

zta.baseline_trusted_devices:
├── device_fingerprint (PK)
├── trust_status: 'trusted' | 'untrusted'
├── last_seen, created_at


#### Performance & Security Analysis
sql
zta.performance_metrics:
├── service_name: Service identifier
├── operation: 'validate' | 'score' | 'decision'
├── duration_ms: Processing time
├── status: 'success' | 'error' └── error_message

zta.security_classifications:
├── original_label: CICIDS ground truth
├── predicted_threats: Detected threats (JSONB)
├── framework_type: 'proposed' | 'baseline'
├── false_positive, false_negative: Accuracy metrics
└── classification_accuracy


#### Views for Analysis
sql
zta.daily_comparison_summary:
├── Framework performance by day
├── Decision distribution
├── Average risk scores
└── Processing times

zta.security_accuracy_summary:
├── Classification accuracy by framework
├── False positive/negative rates
└── Threat detection effectiveness


## 🔗 Service Interactions

### Service Communication Matrix

| Service | Port | Dependencies | Purpose |
|-|||-|
| **elasticsearch** | 9200 | None | Event storage & search |
| **kibana**        | 5601 | elasticsearch | Visualization dashboard |
| **validation**    | 8001 | elasticsearch, data files | Signal enrichment |
| **trust**         | 8002 | validation | Risk scoring |
| **gateway**       | 8003 | trust, validation | Final decisions |
| **siem**          | 8010 | elasticsearch | Threat detection |
| **baseline**      | 8020 | database | Traditional MFA |
| **metrics**       | 8030 | database | Performance analysis |
| **simulator**     | - | all services | Data generation |

### API Endpoints

#### Proposed Framework APIs

POST /validate (validation:8001)
├── Input: {"signals": {...}}
└── Output: {"validated": {...}, "quality": {...}, "enrichment": {...}}

POST /score (trust:8002)
├── Input: {"validated": {...}, "siem": {...}}
└── Output: {"risk": 0.0-1.0, "factors": [...]}

POST /decision (gateway:8003)
├── Input: {"validated": {...}, "siem": {...}}
└── Output: {"decision": "allow|step_up|deny", "risk": 0.0-1.0, "enforcement": "..."}


#### Baseline Framework API

POST /decision (baseline:8020)
├── Input: {"signals": {...}}
└── Output: {"decision": "allow|step_up|deny", "risk_score": 0.0-1.0, "factors": [...]}


#### Health & Monitoring

GET /health (all services)
GET /stats (baseline:8020)
GET /comparison (baseline:8020)
GET /metrics (metrics:8030)


## 🧪 Simulation & Evaluation

### Simulation Process

#### 1. Enhanced Simulator
**File:** `scripts/simulator/enhanced_sim.py`

Process Flow:
├── Load datasets from /data/*
├── Setup STRIDE scenario buckets
├── For each CICIDS sample:
│   ├── Select WiFi, TLS, Device data
│   ├── Apply STRIDE scenario
│   ├── Call Proposed Framework
│   ├── Call Baseline Framework
│   ├── Store comparison results
│   └── Sleep between requests
└── Generate performance report


#### 2. STRIDE Scenario Generation

Scenario Distribution:
├── Spoofing (20%): GPS-WiFi location mismatch
├── Tampering (15%): Malicious TLS fingerprints
├── Repudiation (15%): Benign with audit trail issues
├── Info Disclosure (15%): Data exfiltration patterns
├── DOS (20%): Network flooding attacks
└── Elevation of Privilege (15%): Web application attacks


#### 3. Evaluation Metrics

Performance Metrics:
├── Processing time per framework
├── Decision accuracy vs ground truth
├── False positive/negative rates
├── Risk score distribution
└── Threat detection effectiveness

Security Metrics:
├── STRIDE category detection rates
├── Attack scenario recognition
├── Multi-source correlation effectiveness
└── Framework comparison analysis


## 📁 File Structure

### Core Framework Files

multi-source-mfa-zta-framework/
├── services/
│   ├── validation/
│   │   ├── app/
│   │   │   ├── main.py              # Validation service API
│   │   │   └── enrichment.py        # Data enrichment logic
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── trust/
│   │   ├── app/
│   │   │   └── main.py              # Trust engine & risk scoring
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── gateway/
│   │   ├── app/
│   │   │   └── main.py              # Final decision gateway
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── baseline/
│   │   ├── app/
│   │   │   └── main.py              # Baseline MFA service
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── siem/
│   │   ├── app/
│   │   │   └── main.py              # SIEM threat detection
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   └── metrics/
│       ├── app/
│       │   └── main.py              # Performance metrics
│       ├── Dockerfile
│       └── requirements.txt
├── scripts/
│   ├── simulator/
│   │   ├── enhanced_sim.py          # Main simulation engine
│   │   ├── sim.py                   # Original simulator
│   │   ├── start_simulation.py      # Service health check & startup
│   │   ├── run_enhanced.py          # Standalone runner
│   │   ├── Dockerfile
│   │   └── requirements.txt
│   ├── test_db_connection.py        # Database connectivity test
│   └── verify_data_insertion.py    # Data verification script
├── data/
│   ├── cicids/*.csv                 # Network traffic datasets
│   ├── wifi/wigle_sample.csv        # WiFi location data
│   ├── device_posture/device_posture.csv  # Device security data
│   ├── tls/ja3_fingerprints.csv     # TLS fingerprint data
│   └── geolite2/GeoLite2-City.mmdb  # GeoIP database
├── database/
│   └── schema_extension.sql         # Database schema definition
├── compose/
│   ├── docker-compose.yml           # Service orchestration
│   └── .env                         # Environment configuration
├── .env.sample                      # Environment template
├── SETUP_GUIDE.md                   # Setup instructions
└── SYSTEM_ARCHITECTURE.md          # This document


### Configuration Files

Environment Variables (.env):
├── Database: DB_DSN, PGOPTIONS
├── Elasticsearch: ES_HOST, ES_USER, ES_PASS
├── Service URLs: VALIDATE_URL, GATEWAY_URL, BASELINE_URL
├── Simulation: SIM_SLEEP, SIM_MAX_ROWS, STRIDE percentages
├── Trust Engine: ALLOW_T, DENY_T, SIEM thresholds
└── Security: TOTP_SECRET, SSL settings


## 🚀 Deployment & Operations

### Docker Compose Services
yaml
services:
  elasticsearch:    # Event storage & search
  kibana:          # Visualization dashboard
  validation:      # Signal enrichment (proposed)
  trust:           # Risk scoring (proposed)  
  gateway:         # Decision engine (proposed)
  siem:            # Threat detection
  baseline:        # Traditional MFA
  metrics:         # Performance analysis
  simulator:       # Data generation & testing


### Startup Sequence

1. Elasticsearch & Kibana (data layer)
2. Core services (validation, trust, gateway, baseline, siem, metrics)
3. Health checks & service readiness
4. Simulator execution (data generation)
5. Database storage & analysis


### Data Flow Summary

Raw Data → STRIDE Scenarios → Dual Framework Processing → Comparative Analysis

├── Input: Multi-source datasets (CICIDS, WiFi, Device, TLS)
├── Processing: 
│   ├── Proposed: Validation → Trust → Gateway
│   └── Baseline: Direct decision logic
├── Storage: Framework comparison data
└── Output: Performance metrics & security analysis


### Monitoring & Analysis

Performance Monitoring:
├── Processing times per service
├── Decision accuracy rates  
├── Resource utilization
└── Error rates & reliability

Security Analysis:
├── Threat detection effectiveness
├── False positive/negative analysis
├── STRIDE scenario coverage
└── Framework comparison metrics


## 🎯 Research Evaluation Points

This system enables comprehensive evaluation of:

1. **Multi-source Authentication Effectiveness** - Proposed vs Baseline
2. **STRIDE Threat Model Coverage** - All 6 categories tested
3. **Real-world Data Validation** - Actual CICIDS network data
4. **Performance vs Security Trade-offs** - Processing time vs accuracy
5. **Scalability Analysis** - Large dataset processing capability
6. **Framework Comparison Metrics** - Side-by-side performance analysis

The architecture provides a complete research platform for evaluating advanced Zero Trust Architecture approaches against traditional MFA systems using real-world datasets and comprehensive threat scenarios.