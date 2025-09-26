-- Migration: Fix SIEM alert duplicates by adding unique constraint
-- This prevents duplicate alerts for the same session_id and source combination

BEGIN;

-- First, remove any existing duplicates before adding the constraint
WITH duplicates AS (
    SELECT id,
           ROW_NUMBER() OVER (
               PARTITION BY session_id, source, stride, severity
               ORDER BY created_at DESC
           ) as rn
    FROM zta.siem_alerts
    WHERE source LIKE 'es:mfa-events%'
)
DELETE FROM zta.siem_alerts
WHERE id IN (
    SELECT id FROM duplicates WHERE rn > 1
);

-- Add unique constraint to prevent future duplicates
-- Using session_id + source + stride combination to allow multiple alerts
-- per session but prevent exact duplicates from the same source
ALTER TABLE zta.siem_alerts
ADD CONSTRAINT siem_alerts_unique_session_source_stride
UNIQUE (session_id, source, stride);

-- Add index for better query performance on common lookups
CREATE INDEX IF NOT EXISTS idx_siem_alerts_session_created
ON zta.siem_alerts (session_id, created_at DESC);

-- Add comment for documentation
COMMENT ON CONSTRAINT siem_alerts_unique_session_source_stride ON zta.siem_alerts
IS 'Prevents duplicate SIEM alerts for same session, source, and STRIDE category';

COMMIT;
