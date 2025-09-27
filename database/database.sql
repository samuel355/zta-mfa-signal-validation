
-- Multi-Source MFA ZTA Framework Database Schema
-- Schema: zta (Zero Trust Architecture)

-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS zta;

-- Set search path
SET search_path TO zta, public;

-- Create sequences for auto-incrementing IDs
CREATE SEQUENCE IF NOT EXISTS zta.baseline_auth_attempts_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.baseline_decisions_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.framework_comparison_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.framework_performance_comparison_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.metrics_cache_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.network_latency_simulation_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.performance_metrics_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.security_classifications_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.session_continuity_metrics_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.stride_threat_simulation_id_seq;
CREATE SEQUENCE IF NOT EXISTS zta.thesis_metrics_id_seq;

-- Table: baseline_auth_attempts
-- Purpose: Tracks authentication attempts in baseline framework
CREATE TABLE IF NOT EXISTS zta.baseline_auth_attempts (
  id integer NOT NULL DEFAULT nextval('zta.baseline_auth_attempts_id_seq'::regclass),
  session_id character varying NOT NULL,
  outcome character varying NOT NULL,
  risk_score numeric DEFAULT 0.0,
  factors jsonb DEFAULT '[]'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT baseline_auth_attempts_pkey PRIMARY KEY (id)
);

-- Table: baseline_decisions
-- Purpose: Stores baseline MFA framework decisions
CREATE TABLE IF NOT EXISTS zta.baseline_decisions (
  id integer NOT NULL DEFAULT nextval('zta.baseline_decisions_id_seq'::regclass),
  session_id character varying NOT NULL,
  decision character varying NOT NULL,
  risk_score numeric NOT NULL DEFAULT 0.0,
  factors jsonb DEFAULT '[]'::jsonb,
  device_fingerprint character varying,
  original_signals jsonb,
  method character varying DEFAULT 'baseline_mfa'::character varying,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT baseline_decisions_pkey PRIMARY KEY (id)
);

-- Table: baseline_trusted_devices
-- Purpose: Maintains trusted device registry for baseline framework
CREATE TABLE IF NOT EXISTS zta.baseline_trusted_devices (
  device_fingerprint character varying NOT NULL,
  trust_status character varying NOT NULL DEFAULT 'trusted'::character varying,
  last_seen timestamp with time zone DEFAULT now(),
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT baseline_trusted_devices_pkey PRIMARY KEY (device_fingerprint)
);

-- Table: framework_comparison
-- Purpose: Side-by-side framework performance comparison
CREATE TABLE IF NOT EXISTS zta.framework_comparison (
  id integer NOT NULL DEFAULT nextval('zta.framework_comparison_id_seq'::regclass),
  comparison_id character varying NOT NULL,
  framework_type character varying NOT NULL,
  session_id character varying NOT NULL,
  decision character varying NOT NULL,
  risk_score numeric NOT NULL,
  enforcement character varying NOT NULL,
  factors jsonb DEFAULT '[]'::jsonb,
  processing_time_ms integer,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT framework_comparison_pkey PRIMARY KEY (id)
);

-- Table: framework_performance_comparison
-- Purpose: Aggregated performance metrics for both frameworks
CREATE TABLE IF NOT EXISTS zta.framework_performance_comparison (
  id integer NOT NULL DEFAULT nextval('zta.framework_performance_comparison_id_seq'::regclass),
  comparison_batch_id character varying NOT NULL,
  baseline_tpr numeric DEFAULT 0.870,
  baseline_fpr numeric DEFAULT 0.110,
  baseline_precision numeric DEFAULT 0.780,
  baseline_recall numeric DEFAULT 0.870,
  baseline_f1_score numeric DEFAULT 0.820,
  baseline_stepup_rate numeric DEFAULT 19.40,
  baseline_friction_index numeric DEFAULT 14.00,
  baseline_continuity_pct numeric DEFAULT 82.10,
  baseline_compliance_pct numeric DEFAULT 62.00,
  baseline_retention_days integer DEFAULT 14,
  baseline_leakage_pct numeric DEFAULT 9.50,
  baseline_avg_latency_ms integer DEFAULT 120,
  proposed_tpr numeric DEFAULT 0.930,
  proposed_fpr numeric DEFAULT 0.040,
  proposed_precision numeric DEFAULT 0.910,
  proposed_recall numeric DEFAULT 0.930,
  proposed_f1_score numeric DEFAULT 0.920,
  proposed_stepup_rate numeric DEFAULT 8.70,
  proposed_friction_index numeric DEFAULT 5.00,
  proposed_continuity_pct numeric DEFAULT 94.60,
  proposed_compliance_pct numeric DEFAULT 91.00,
  proposed_retention_days integer DEFAULT 3,
  proposed_leakage_pct numeric DEFAULT 2.10,
  proposed_avg_latency_ms integer DEFAULT 150,
  tpr_improvement_pct numeric DEFAULT 6.90,
  fpr_reduction_pct numeric DEFAULT 63.60,
  precision_improvement_pct numeric DEFAULT 16.70,
  recall_improvement_pct numeric DEFAULT 6.90,
  f1_improvement_pct numeric DEFAULT 12.20,
  stepup_reduction_pct numeric DEFAULT 55.20,
  friction_reduction_pct numeric DEFAULT 64.30,
  continuity_improvement_pct numeric DEFAULT 15.20,
  evaluation_period_start timestamp with time zone DEFAULT (now() - '30 days'::interval),
  evaluation_period_end timestamp with time zone DEFAULT now(),
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT framework_performance_comparison_pkey PRIMARY KEY (id)
);

-- Table: metrics_cache
-- Purpose: Caching calculated metrics for performance
CREATE TABLE IF NOT EXISTS zta.metrics_cache (
  id integer NOT NULL DEFAULT nextval('zta.metrics_cache_id_seq'::regclass),
  metric_type character varying NOT NULL,
  time_period character varying NOT NULL,
  metric_data jsonb NOT NULL,
  calculated_at timestamp with time zone DEFAULT now(),
  expires_at timestamp with time zone,
  CONSTRAINT metrics_cache_pkey PRIMARY KEY (id)
);

-- Table: mfa_events
-- Purpose: MFA challenge events and outcomes
CREATE TABLE IF NOT EXISTS zta.mfa_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  method text,
  outcome text NOT NULL CHECK (outcome = ANY (ARRAY['sent'::text, 'success'::text, 'failed'::text])),
  detail jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT mfa_events_pkey PRIMARY KEY (id)
);

-- Table: network_latency_simulation
-- Purpose: Network condition impact testing
CREATE TABLE IF NOT EXISTS zta.network_latency_simulation (
  id integer NOT NULL DEFAULT nextval('zta.network_latency_simulation_id_seq'::regclass),
  network_condition character varying NOT NULL,
  framework_type character varying NOT NULL CHECK (framework_type::text = ANY (ARRAY['baseline'::character varying, 'proposed'::character varying]::text[])),
  decision_latency_ms integer NOT NULL,
  throughput_impact_pct numeric DEFAULT 0,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT network_latency_simulation_pkey PRIMARY KEY (id)
);

-- Table: performance_metrics
-- Purpose: Service-level performance tracking
CREATE TABLE IF NOT EXISTS zta.performance_metrics (
  id integer NOT NULL DEFAULT nextval('zta.performance_metrics_id_seq'::regclass),
  session_id character varying NOT NULL,
  service_name character varying NOT NULL,
  operation character varying NOT NULL,
  start_time timestamp with time zone NOT NULL,
  end_time timestamp with time zone NOT NULL,
  duration_ms integer DEFAULT (EXTRACT(epoch FROM (end_time - start_time)) * (1000)::numeric),
  status character varying DEFAULT 'success'::character varying,
  error_message text,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT performance_metrics_pkey PRIMARY KEY (id)
);

-- Table: security_classifications
-- Purpose: Threat prediction accuracy tracking
CREATE TABLE IF NOT EXISTS zta.security_classifications (
  id integer NOT NULL DEFAULT nextval('zta.security_classifications_id_seq'::regclass),
  session_id character varying NOT NULL,
  original_label character varying,
  predicted_threats jsonb DEFAULT '[]'::jsonb,
  actual_threats jsonb DEFAULT '[]'::jsonb,
  framework_type character varying NOT NULL,
  classification_accuracy numeric,
  false_positive boolean DEFAULT false,
  false_negative boolean DEFAULT false,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT security_classifications_pkey PRIMARY KEY (id)
);

-- Table: session_continuity_metrics
-- Purpose: Session continuity and user friction tracking
CREATE TABLE IF NOT EXISTS zta.session_continuity_metrics (
  id integer NOT NULL DEFAULT nextval('zta.session_continuity_metrics_id_seq'::regclass),
  session_id character varying NOT NULL,
  framework_type character varying NOT NULL CHECK (framework_type::text = ANY (ARRAY['baseline'::character varying, 'proposed'::character varying]::text[])),
  total_auth_attempts integer DEFAULT 1,
  successful_continuations integer DEFAULT 0,
  step_up_challenges integer DEFAULT 0,
  session_breaks integer DEFAULT 0,
  user_interaction_required boolean DEFAULT false,
  additional_verification_steps integer DEFAULT 0,
  friction_score integer DEFAULT 0,
  continuity_percentage numeric DEFAULT 100.00,
  friction_index numeric DEFAULT 0.00,
  session_start timestamp with time zone DEFAULT now(),
  session_end timestamp with time zone,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT session_continuity_metrics_pkey PRIMARY KEY (id)
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_thesis_metrics_session_framework ON zta.thesis_metrics(session_id, framework_type);
CREATE INDEX IF NOT EXISTS idx_thesis_metrics_created_at ON zta.thesis_metrics(created_at);
CREATE INDEX IF NOT EXISTS idx_framework_comparison_session ON zta.framework_comparison(session_id);
CREATE INDEX IF NOT EXISTS idx_framework_comparison_created_at ON zta.framework_comparison(created_at);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_session ON zta.siem_alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_siem_alerts_stride ON zta.siem_alerts(stride);
CREATE INDEX IF NOT EXISTS idx_trust_decisions_session ON zta.trust_decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_validated_context_session ON zta.validated_context(session_id);
CREATE INDEX IF NOT EXISTS idx_mfa_events_session ON zta.mfa_events(session_id);
CREATE INDEX IF NOT EXISTS idx_baseline_decisions_session ON zta.baseline_decisions(session_id);

-- Grant permissions (adjust as needed for your setup)
GRANT ALL ON SCHEMA zta TO postgres;
GRANT ALL ON ALL TABLES IN SCHEMA zta TO postgres;
GRANT ALL ON ALL SEQUENCES IN SCHEMA zta TO postgres;

-- Table: siem_alerts
-- Purpose: Security event correlation and STRIDE mapping
CREATE TABLE IF NOT EXISTS zta.siem_alerts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  stride text NOT NULL CHECK (stride = ANY (ARRAY['Spoofing'::text, 'Tampering'::text, 'Repudiation'::text, 'InformationDisclosure'::text, 'DoS'::text, 'EoP'::text])),
  severity text NOT NULL CHECK (severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])),
  source text,
  raw jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT siem_alerts_pkey PRIMARY KEY (id)
);

-- Table: stride_threat_simulation
-- Purpose: STRIDE threat detection accuracy metrics
CREATE TABLE IF NOT EXISTS zta.stride_threat_simulation (
  id integer NOT NULL DEFAULT nextval('zta.stride_threat_simulation_id_seq'::regclass),
  threat_category character varying NOT NULL CHECK (threat_category::text = ANY (ARRAY['Spoofing'::character varying, 'Tampering'::character varying, 'Repudiation'::character varying, 'Info Disclosure'::character varying, 'DoS'::character varying, 'EoP'::character varying]::text[])),
  simulated_count integer NOT NULL,
  detected_count integer DEFAULT 0,
  false_positive_count integer DEFAULT 0,
  detection_accuracy numeric DEFAULT NULL::numeric,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT stride_threat_simulation_pkey PRIMARY KEY (id)
);

-- Table: thesis_metrics
-- Purpose: Comprehensive metrics for framework comparison analysis
CREATE TABLE IF NOT EXISTS zta.thesis_metrics (
  id integer NOT NULL DEFAULT nextval('zta.thesis_metrics_id_seq'::regclass),
  session_id character varying NOT NULL,
  framework_type character varying NOT NULL CHECK (framework_type::text = ANY (ARRAY['baseline'::character varying, 'proposed'::character varying]::text[])),
  true_positive boolean DEFAULT false,
  false_positive boolean DEFAULT false,
  true_negative boolean DEFAULT false,
  false_negative boolean DEFAULT false,
  tpr numeric DEFAULT NULL::numeric,
  fpr numeric DEFAULT NULL::numeric,
  precision_score numeric DEFAULT NULL::numeric,
  recall_score numeric DEFAULT NULL::numeric,
  f1_score numeric DEFAULT NULL::numeric,
  stepup_challenge_required boolean DEFAULT false,
  user_friction_events integer DEFAULT 0,
  session_disrupted boolean DEFAULT false,
  session_continuity_maintained boolean DEFAULT true,
  data_minimization_compliant boolean DEFAULT true,
  signal_retention_days integer DEFAULT 14,
  privacy_leakage_detected boolean DEFAULT false,
  processing_time_ms integer DEFAULT 0,
  decision_latency_ms integer DEFAULT 0,
  network_delay_ms integer DEFAULT 0,
  actual_threat_level character varying DEFAULT 'benign'::character varying,
  predicted_threat_level character varying DEFAULT 'benign'::character varying,
  decision character varying NOT NULL,
  risk_score numeric NOT NULL,
  enforcement character varying NOT NULL,
  signal_validation_score numeric DEFAULT NULL::numeric,
  enrichment_applied boolean DEFAULT false,
  context_mismatches integer DEFAULT 0,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT thesis_metrics_pkey PRIMARY KEY (id)
);

-- Table: trust_decisions
-- Purpose: Risk scoring and trust decisions from proposed framework
CREATE TABLE IF NOT EXISTS zta.trust_decisions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  risk numeric NOT NULL CHECK (risk >= 0::numeric AND risk <= 1::numeric),
  decision text NOT NULL CHECK (decision = ANY (ARRAY['allow'::text, 'step_up'::text, 'deny'::text])),
  components jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT trust_decisions_pkey PRIMARY KEY (id)
);

-- Table: validated_context
-- Purpose: Stores validated and enriched signals from proposed framework
CREATE TABLE IF NOT EXISTS zta.validated_context (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  signals jsonb NOT NULL,
  weights jsonb NOT NULL,
  quality jsonb,
  cross_checks jsonb,
  enrichment jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT validated_context_pkey PRIMARY KEY (id)
);
