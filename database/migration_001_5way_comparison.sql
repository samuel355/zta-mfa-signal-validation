-- Migration: Expand framework_type CHECK constraints for 5-way comparison
-- Run this once in Supabase SQL editor (Dashboard > SQL Editor)
-- Adds: ablation, ahmadi2025, jimmy2025, phani2025 alongside existing 'proposed'

SET search_path TO zta, public;

-- ── thesis_metrics ────────────────────────────────────────────────────────────
ALTER TABLE zta.thesis_metrics
  DROP CONSTRAINT IF EXISTS thesis_metrics_framework_type_check;

ALTER TABLE zta.thesis_metrics
  ADD CONSTRAINT thesis_metrics_framework_type_check
  CHECK (framework_type IN ('proposed','ablation','ahmadi2025','jimmy2025','phani2025'));

-- ── network_latency_simulation ────────────────────────────────────────────────
ALTER TABLE zta.network_latency_simulation
  DROP CONSTRAINT IF EXISTS network_latency_simulation_framework_type_check;

ALTER TABLE zta.network_latency_simulation
  ADD CONSTRAINT network_latency_simulation_framework_type_check
  CHECK (framework_type IN ('proposed','ablation','ahmadi2025','jimmy2025','phani2025'));

-- ── session_continuity_metrics ────────────────────────────────────────────────
ALTER TABLE zta.session_continuity_metrics
  DROP CONSTRAINT IF EXISTS session_continuity_metrics_framework_type_check;

ALTER TABLE zta.session_continuity_metrics
  ADD CONSTRAINT session_continuity_metrics_framework_type_check
  CHECK (framework_type IN ('proposed','ablation','ahmadi2025','jimmy2025','phani2025'));
