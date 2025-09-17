-- Database schema extension for baseline comparison and metrics collection
-- This extends the existing ZTA framework schema

-- Create schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS zta;

-- Baseline MFA decisions table
CREATE TABLE IF NOT EXISTS zta.baseline_decisions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    decision VARCHAR(50) NOT NULL, -- 'allow', 'deny', 'step_up'
    risk_score DECIMAL(5,3) NOT NULL DEFAULT 0.0,
    factors JSONB DEFAULT '[]'::jsonb, -- array of decision factors
    device_fingerprint VARCHAR(255),
    original_signals JSONB, -- original signals for comparison
    method VARCHAR(100) DEFAULT 'baseline_mfa',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Baseline authentication attempts
CREATE TABLE IF NOT EXISTS zta.baseline_auth_attempts (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    outcome VARCHAR(50) NOT NULL, -- 'success', 'failed', 'mfa_required'
    risk_score DECIMAL(5,3) DEFAULT 0.0,
    factors JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Baseline trusted devices
CREATE TABLE IF NOT EXISTS zta.baseline_trusted_devices (
    device_fingerprint VARCHAR(255) PRIMARY KEY,
    trust_status VARCHAR(50) NOT NULL DEFAULT 'trusted', -- 'trusted', 'untrusted'
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Metrics aggregation cache (for performance)
CREATE TABLE IF NOT EXISTS zta.metrics_cache (
    id SERIAL PRIMARY KEY,
    metric_type VARCHAR(100) NOT NULL, -- 'security', 'performance', 'detection', 'decision'
    time_period VARCHAR(50) NOT NULL, -- '1h', '24h', '7d', etc.
    metric_data JSONB NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

-- Comparison results storage
CREATE TABLE IF NOT EXISTS zta.framework_comparison (
    id SERIAL PRIMARY KEY,
    comparison_id VARCHAR(255) NOT NULL,
    framework_type VARCHAR(50) NOT NULL, -- 'proposed', 'baseline'
    session_id VARCHAR(255) NOT NULL,
    decision VARCHAR(50) NOT NULL,
    risk_score DECIMAL(5,3) NOT NULL,
    enforcement VARCHAR(100) NOT NULL,
    factors JSONB DEFAULT '[]'::jsonb,
    processing_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Performance metrics for detailed analysis
CREATE TABLE IF NOT EXISTS zta.performance_metrics (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    service_name VARCHAR(100) NOT NULL, -- 'validation', 'trust', 'gateway', 'baseline'
    operation VARCHAR(100) NOT NULL, -- 'validate', 'score', 'decision'
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    duration_ms INTEGER GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (end_time - start_time)) * 1000
    ) STORED,
    status VARCHAR(50) DEFAULT 'success', -- 'success', 'error', 'timeout'
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security event classification for analysis
CREATE TABLE IF NOT EXISTS zta.security_classifications (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) NOT NULL,
    original_label VARCHAR(100), -- from CICIDS dataset
    predicted_threats JSONB DEFAULT '[]'::jsonb, -- detected threats
    actual_threats JSONB DEFAULT '[]'::jsonb, -- ground truth if available
    framework_type VARCHAR(50) NOT NULL, -- 'proposed', 'baseline'
    classification_accuracy DECIMAL(5,3), -- if ground truth available
    false_positive BOOLEAN DEFAULT FALSE,
    false_negative BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_baseline_decisions_session_id ON zta.baseline_decisions(session_id);
CREATE INDEX IF NOT EXISTS idx_baseline_decisions_created_at ON zta.baseline_decisions(created_at);
CREATE INDEX IF NOT EXISTS idx_baseline_decisions_decision ON zta.baseline_decisions(decision);

CREATE INDEX IF NOT EXISTS idx_baseline_auth_attempts_session_id ON zta.baseline_auth_attempts(session_id);
CREATE INDEX IF NOT EXISTS idx_baseline_auth_attempts_created_at ON zta.baseline_auth_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_baseline_auth_attempts_outcome ON zta.baseline_auth_attempts(outcome);

CREATE INDEX IF NOT EXISTS idx_metrics_cache_type_period ON zta.metrics_cache(metric_type, time_period);
CREATE INDEX IF NOT EXISTS idx_metrics_cache_expires_at ON zta.metrics_cache(expires_at);

CREATE INDEX IF NOT EXISTS idx_framework_comparison_comparison_id ON zta.framework_comparison(comparison_id);
CREATE INDEX IF NOT EXISTS idx_framework_comparison_framework_type ON zta.framework_comparison(framework_type);
CREATE INDEX IF NOT EXISTS idx_framework_comparison_created_at ON zta.framework_comparison(created_at);

CREATE INDEX IF NOT EXISTS idx_performance_metrics_session_id ON zta.performance_metrics(session_id);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_service ON zta.performance_metrics(service_name);
CREATE INDEX IF NOT EXISTS idx_performance_metrics_created_at ON zta.performance_metrics(created_at);

CREATE INDEX IF NOT EXISTS idx_security_classifications_session_id ON zta.security_classifications(session_id);
CREATE INDEX IF NOT EXISTS idx_security_classifications_framework_type ON zta.security_classifications(framework_type);
CREATE INDEX IF NOT EXISTS idx_security_classifications_created_at ON zta.security_classifications(created_at);

-- GIN indexes for JSONB columns for faster queries
CREATE INDEX IF NOT EXISTS idx_baseline_decisions_factors_gin ON zta.baseline_decisions USING GIN(factors);
CREATE INDEX IF NOT EXISTS idx_framework_comparison_factors_gin ON zta.framework_comparison USING GIN(factors);
CREATE INDEX IF NOT EXISTS idx_security_classifications_threats_gin ON zta.security_classifications USING GIN(predicted_threats);

-- Views for common queries
CREATE OR REPLACE VIEW zta.daily_comparison_summary AS
SELECT
    DATE(created_at) as date,
    framework_type,
    COUNT(*) as total_decisions,
    COUNT(*) FILTER (WHERE decision = 'allow') as allow_count,
    COUNT(*) FILTER (WHERE decision = 'step_up') as stepup_count,
    COUNT(*) FILTER (WHERE decision = 'deny') as deny_count,
    AVG(risk_score) as avg_risk_score,
    AVG(processing_time_ms) as avg_processing_time
FROM zta.framework_comparison
WHERE created_at >= CURRENT_DATE - INTERVAL '30 days'
GROUP BY DATE(created_at), framework_type
ORDER BY date DESC, framework_type;

CREATE OR REPLACE VIEW zta.security_accuracy_summary AS
SELECT
    framework_type,
    COUNT(*) as total_classifications,
    COUNT(*) FILTER (WHERE false_positive = TRUE) as false_positives,
    COUNT(*) FILTER (WHERE false_negative = TRUE) as false_negatives,
    AVG(classification_accuracy) as avg_accuracy,
    COUNT(*) FILTER (WHERE classification_accuracy IS NOT NULL) as accuracy_samples
FROM zta.security_classifications
WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
GROUP BY framework_type;

-- Function to clean up old metrics cache
CREATE OR REPLACE FUNCTION zta.cleanup_expired_metrics()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM zta.metrics_cache WHERE expires_at < NOW();
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate framework comparison metrics
CREATE OR REPLACE FUNCTION zta.get_framework_comparison_metrics(hours_back INTEGER DEFAULT 24)
RETURNS TABLE(
    framework_type VARCHAR(50),
    total_events BIGINT,
    success_rate DECIMAL(5,2),
    mfa_rate DECIMAL(5,2),
    deny_rate DECIMAL(5,2),
    avg_risk_score DECIMAL(5,3),
    avg_processing_time DECIMAL(10,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        fc.framework_type,
        COUNT(*) as total_events,
        (COUNT(*) FILTER (WHERE fc.decision = 'allow') * 100.0 / COUNT(*))::DECIMAL(5,2) as success_rate,
        (COUNT(*) FILTER (WHERE fc.decision = 'step_up') * 100.0 / COUNT(*))::DECIMAL(5,2) as mfa_rate,
        (COUNT(*) FILTER (WHERE fc.decision = 'deny') * 100.0 / COUNT(*))::DECIMAL(5,2) as deny_rate,
        AVG(fc.risk_score)::DECIMAL(5,3) as avg_risk_score,
        AVG(fc.processing_time_ms)::DECIMAL(10,2) as avg_processing_time
    FROM zta.framework_comparison fc
    WHERE fc.created_at > NOW() - (hours_back || ' hours')::INTERVAL
    GROUP BY fc.framework_type;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE zta.baseline_decisions IS 'Stores decisions made by the baseline MFA system for comparison';
COMMENT ON TABLE zta.baseline_auth_attempts IS 'Tracks authentication attempts in the baseline system';
COMMENT ON TABLE zta.baseline_trusted_devices IS 'Maintains list of trusted devices in the baseline system';
COMMENT ON TABLE zta.metrics_cache IS 'Caches computed metrics for performance optimization';
COMMENT ON TABLE zta.framework_comparison IS 'Stores side-by-side comparison data between proposed and baseline frameworks';
COMMENT ON TABLE zta.performance_metrics IS 'Detailed performance timing data for all services';
COMMENT ON TABLE zta.security_classifications IS 'Security event classification data for accuracy analysis';

COMMENT ON VIEW zta.daily_comparison_summary IS 'Daily summary of framework comparison metrics';
COMMENT ON VIEW zta.security_accuracy_summary IS 'Security classification accuracy summary by framework';

COMMENT ON FUNCTION zta.cleanup_expired_metrics() IS 'Removes expired entries from metrics cache';
COMMENT ON FUNCTION zta.get_framework_comparison_metrics(INTEGER) IS 'Returns comparative metrics between frameworks';
