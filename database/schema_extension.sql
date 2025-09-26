-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE zta.baseline_auth_attempts (
  id integer NOT NULL DEFAULT nextval('zta.baseline_auth_attempts_id_seq'::regclass),
  session_id character varying NOT NULL,
  outcome character varying NOT NULL,
  risk_score numeric DEFAULT 0.0,
  factors jsonb DEFAULT '[]'::jsonb,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT baseline_auth_attempts_pkey PRIMARY KEY (id)
);
CREATE TABLE zta.baseline_decisions (
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
CREATE TABLE zta.baseline_trusted_devices (
  device_fingerprint character varying NOT NULL,
  trust_status character varying NOT NULL DEFAULT 'trusted'::character varying,
  last_seen timestamp with time zone DEFAULT now(),
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT baseline_trusted_devices_pkey PRIMARY KEY (device_fingerprint)
);
CREATE TABLE zta.framework_comparison (
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
CREATE TABLE zta.metrics_cache (
  id integer NOT NULL DEFAULT nextval('zta.metrics_cache_id_seq'::regclass),
  metric_type character varying NOT NULL,
  time_period character varying NOT NULL,
  metric_data jsonb NOT NULL,
  calculated_at timestamp with time zone DEFAULT now(),
  expires_at timestamp with time zone,
  CONSTRAINT metrics_cache_pkey PRIMARY KEY (id)
);
CREATE TABLE zta.mfa_events (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  method text,
  outcome text NOT NULL CHECK (outcome = ANY (ARRAY['sent'::text, 'success'::text, 'failed'::text])),
  detail jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT mfa_events_pkey PRIMARY KEY (id)
);
CREATE TABLE zta.performance_metrics (
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
CREATE TABLE zta.security_classifications (
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
CREATE TABLE zta.siem_alerts (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  stride text NOT NULL CHECK (stride = ANY (ARRAY['Spoofing'::text, 'Tampering'::text, 'Repudiation'::text, 'InformationDisclosure'::text, 'DoS'::text, 'EoP'::text])),
  severity text NOT NULL CHECK (severity = ANY (ARRAY['low'::text, 'medium'::text, 'high'::text])),
  source text,
  raw jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT siem_alerts_pkey PRIMARY KEY (id)
);
CREATE TABLE zta.trust_decisions (
  id uuid NOT NULL DEFAULT gen_random_uuid(),
  session_id text NOT NULL,
  risk numeric NOT NULL CHECK (risk >= 0::numeric AND risk <= 1::numeric),
  decision text NOT NULL CHECK (decision = ANY (ARRAY['allow'::text, 'step_up'::text, 'deny'::text])),
  components jsonb,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  CONSTRAINT trust_decisions_pkey PRIMARY KEY (id)
);
CREATE TABLE zta.validated_context (
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