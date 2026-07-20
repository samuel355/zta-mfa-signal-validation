#!/usr/bin/env python3
"""Generate a non-secret reproducibility manifest for one paired experiment."""

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
import psycopg2.extras


ROOT = Path(__file__).resolve().parents[1]
RUN_ID = os.environ["METRICS_COMPARISON_ID"]
DSN = os.environ["DB_DSN"]

CONFIG_KEYS = [
    "ALLOW_T", "DENY_T", "SIEM_HIGH_BUMP", "SIEM_MED_BUMP",
    "TRUST_BASE_GAIN", "TRUST_FALLBACK_OBSERVED",
    "VALIDATION_CONFIDENCE_THRESHOLD", "DIST_THRESHOLD_KM",
    "TLS_CRITICAL_TAGS", "MISSING_SIGNAL_PENALTY",
    "GEO_MISMATCH_PENALTY", "CRIT_TLS_PENALTY",
    "DEVICE_TLS_MISMATCH_PENALTY", "DEVICE_FRESHNESS_WINDOW_DAYS",
    "SIM_RANDOM_SEED", "SIM_MAX_PER_FILE", "SIM_BENIGN_KEEP",
    "SIM_MIN_WIFI", "SIM_MIN_GPS", "SIM_MIN_TLS", "SIM_MIN_DEVICE",
    "SIM_GPS_OFFSET_KM", "SIM_PCT_SPOOFING", "SIM_RBA_SPOOF_PCT",
    "SIM_PCT_TLS_TAMPERING", "SIM_PCT_DOS", "SIM_PCT_EXFIL", "SIM_EXFIL_MODE",
    "SIM_PCT_EOP", "SIM_PCT_REPUDIATION", "SIM_PCT_BENIGN",
]

CONFIG_DEFAULTS = {
    "MISSING_SIGNAL_PENALTY": "0.3",
    "GEO_MISMATCH_PENALTY": "0.5",
    "CRIT_TLS_PENALTY": "0.2",
    "DEVICE_TLS_MISMATCH_PENALTY": "0.4",
    "DEVICE_FRESHNESS_WINDOW_DAYS": "30",
    "SIM_RANDOM_SEED": "20260720",
}

ARTIFACTS = [
    "datasets/cic2018/02-14-2018.csv",
    "datasets/cic2018/02-15-2018.csv",
    "datasets/cic2018/02-22-2018.csv",
    "datasets/cic2018/02-28-2018.csv",
    "data/rba/rba_sample.csv",
    "data/wifi/wigle_sample.csv",
    "data/device_posture/device_posture.csv",
    "data/tls/ja3_fingerprints.csv",
    "services/validation/models/dos_classifier.joblib",
    "services/validation/models/eop_classifier.joblib",
]


def sha256(path: Path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main():
    conn = psycopg2.connect(
        DSN, connect_timeout=15, cursor_factory=psycopg2.extras.RealDictCursor
    )
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT framework_type, COUNT(*) AS rows,
                       COUNT(DISTINCT session_id) AS sessions,
                       MIN(created_at) AS started_at, MAX(created_at) AS ended_at
                FROM zta.framework_comparison
                WHERE comparison_id = %s
                GROUP BY framework_type ORDER BY framework_type
            """, (RUN_ID,))
            frameworks = [dict(row) for row in cur.fetchall()]
            cur.execute("""
                SELECT COUNT(*) AS sessions,
                       COUNT(*) FILTER (WHERE row_count = 4 AND framework_count = 4)
                           AS complete_sessions
                FROM (
                    SELECT session_id, COUNT(*) AS row_count,
                           COUNT(DISTINCT framework_type) AS framework_count
                    FROM zta.framework_comparison
                    WHERE comparison_id = %s GROUP BY session_id
                ) paired
            """, (RUN_ID,))
            pairing = dict(cur.fetchone())
    finally:
        conn.close()

    files = {}
    for relative in ARTIFACTS:
        path = ROOT / relative
        files[relative] = {
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }

    diff = git("diff", "--binary", "HEAD")
    manifest = {
        "comparison_id": RUN_ID,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": git("rev-parse", "HEAD"),
        "working_tree_diff_sha256": hashlib.sha256(diff.encode()).hexdigest(),
        "working_tree_dirty": bool(git("status", "--porcelain")),
        "pairing": pairing,
        "frameworks": frameworks,
        "configuration": {
            key: os.environ.get(key, CONFIG_DEFAULTS.get(key)) for key in CONFIG_KEYS
        },
        "artifacts": files,
        "notes": [
            "Ground-truth labels are used only for post-decision evaluation.",
            "DoS/EoP live evaluation rows use the deterministic held-out test split.",
            "Jimmy (2025) is excluded because no reproducible scoring equation is published.",
            "Network-condition metrics were not rerun for this comparison ID.",
        ],
    }

    out = ROOT / "scripts" / "experiment_manifest.json"
    out.write_text(json.dumps(manifest, indent=2, default=str) + "\n")
    print(out)


if __name__ == "__main__":
    main()
