#!/usr/bin/env python3
"""
Compute Chapter 4 metrics from the live comparison database.

Excludes Jimmy (2025) — no published formula, so it's excluded from the
head-to-head baseline comparison. Excludes a small warm-up window per
framework (first-request cold-start DB connections skew raw means).

Usage: python3 scripts/compute_chapter4_metrics.py
Writes: scripts/chapter4_metrics.json
"""
import json
import math
import os
from statistics import median

import psycopg2
import psycopg2.extras

DSN = os.environ["DB_DSN"]  # no hardcoded fallback — set via compose/.env, never commit real credentials
WARMUP_N = 5  # first N rows per framework excluded (cold-start connection setup)
FRAMEWORKS = ["proposed", "ablation", "ahmadi2025", "phani2025"]  # Jimmy excluded

RUN_ID = os.environ.get("METRICS_COMPARISON_ID")

STRIDE_LABELS = {
    "Spoofing": "Spoofing",
    "Tampering": "Tampering",
    "Repudiation": "Repudiation",
    "Denial of Service": "Denial of Service",
    "Information Disclosure": "Information Disclosure",
    "Elevation of Privilege": "Escalation of Privilege",
}


def _connect():
    return psycopg2.connect(DSN, connect_timeout=15, cursor_factory=psycopg2.extras.RealDictCursor)


def resolve_run_id(conn):
    """Use an explicitly selected run, or the latest complete four-framework run."""
    if RUN_ID:
        return RUN_ID
    with conn.cursor() as cur:
        cur.execute("""
            SELECT comparison_id
            FROM zta.framework_comparison
            WHERE framework_type = ANY(%s)
            GROUP BY comparison_id
            HAVING COUNT(DISTINCT framework_type) = %s
               AND COUNT(*) = COUNT(DISTINCT session_id || ':' || framework_type)
            ORDER BY MAX(created_at) DESC
            LIMIT 1
        """, (FRAMEWORKS, len(FRAMEWORKS)))
        row = cur.fetchone()
    if not row:
        raise RuntimeError("No complete paired four-framework experiment found")
    return row["comparison_id"]


def _percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * pct
    f, c = int(k), min(int(k) + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


def _wilson(successes, total, z=1.959963984540054):
    if total <= 0:
        return [None, None]
    p = successes / total
    denominator = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return [round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4)]


def latency_stats(conn, run_id):
    out = {}
    with conn.cursor() as cur:
        for fw in FRAMEWORKS:
            cur.execute("""
                SELECT processing_time_ms FROM zta.framework_comparison
                WHERE framework_type = %s AND comparison_id = %s ORDER BY id
            """, (fw, run_id))
            vals = [r["processing_time_ms"] for r in cur.fetchall()]
            skip = WARMUP_N
            # A cold-start artifact (e.g. ES shard allocation after a container
            # rebuild) can inflate a long prefix beyond the standard warm-up
            # window — inspect the raw sequence before trusting this blindly.
            warm = sorted(vals[skip:]) if len(vals) > skip else sorted(vals)
            out[fw] = {
                "n": len(warm),
                "avg_ms": round(sum(warm) / len(warm), 1) if warm else None,
                "median_ms": round(median(warm), 1) if warm else None,
                "p95_ms": round(_percentile(warm, 0.95), 1) if warm else None,
                "p99_ms": round(_percentile(warm, 0.99), 1) if warm else None,
            }
    return out


def decision_distribution(conn, run_id):
    out = {}
    with conn.cursor() as cur:
        for fw in FRAMEWORKS:
            cur.execute("""
                SELECT decision, COUNT(*) as c FROM zta.framework_comparison
                WHERE framework_type = %s AND comparison_id = %s GROUP BY decision
            """, (fw, run_id))
            rows = {r["decision"]: r["c"] for r in cur.fetchall()}
            total = sum(rows.values())
            out[fw] = {
                "total": total,
                "allow": rows.get("allow", 0),
                "step_up": rows.get("step_up", 0),
                "deny": rows.get("deny", 0),
                "step_up_rate_pct": round(100 * rows.get("step_up", 0) / max(1, total), 2),
            }
    return out


def usability_benign_only(conn, run_id):
    """Step-up/deny rate restricted to genuinely BENIGN sessions — the metric
    that reflects actual user friction, since the all-sessions rate is
    dominated by the dataset's deliberate attack oversampling."""
    out = {}
    with conn.cursor() as cur:
        for fw in FRAMEWORKS:
            cur.execute("""
                SELECT fc.decision, COUNT(*) as c
                FROM zta.framework_comparison fc
                JOIN zta.security_classifications sc
                  ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
                WHERE fc.framework_type = %s AND fc.comparison_id = %s
                  AND UPPER(COALESCE(sc.original_label, 'BENIGN')) = 'BENIGN'
                GROUP BY fc.decision
            """, (fw, run_id))
            rows = {r["decision"]: r["c"] for r in cur.fetchall()}
            total = sum(rows.values())
            out[fw] = {
                "n_benign": total,
                "allow": rows.get("allow", 0),
                "step_up": rows.get("step_up", 0),
                "deny": rows.get("deny", 0),
                "step_up_rate_pct": round(100 * rows.get("step_up", 0) / max(1, total), 2),
                "any_friction_rate_pct": round(100 * (rows.get("step_up", 0) + rows.get("deny", 0)) / max(1, total), 2),
            }
    return out


def security_accuracy(conn, run_id):
    out = {}
    with conn.cursor() as cur:
        for fw in FRAMEWORKS:
            cur.execute("""
                SELECT sc.original_label, sc.false_positive, sc.false_negative
                FROM zta.security_classifications sc
                JOIN zta.framework_comparison fc
                  ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
                WHERE sc.framework_type = %s AND fc.comparison_id = %s
            """, (fw, run_id))
            rows = cur.fetchall()
            tp = tn = fp = fn = 0
            for r in rows:
                is_malicious = (r["original_label"] or "BENIGN").upper() != "BENIGN"
                if r["false_positive"]:
                    fp += 1
                elif r["false_negative"]:
                    fn += 1
                elif is_malicious:
                    tp += 1
                else:
                    tn += 1
            tpr = tp / max(1, tp + fn)
            fpr = fp / max(1, fp + tn)
            precision = tp / max(1, tp + fp)
            f1 = 2 * precision * tpr / max(1e-9, precision + tpr)
            accuracy = (tp + tn) / max(1, tp + tn + fp + fn)
            out[fw] = {
                "n": len(rows), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                "tpr": round(tpr, 4), "fpr": round(fpr, 4),
                "precision": round(precision, 4), "f1": round(f1, 4),
                "accuracy": round(accuracy, 4),
                "tpr_95ci": _wilson(tp, tp + fn),
                "fpr_95ci": _wilson(fp, fp + tn),
                "precision_95ci": _wilson(tp, tp + fp),
                "accuracy_95ci": _wilson(tp + tn, tp + tn + fp + fn),
            }
    return out


def stride_distribution(conn, run_id):
    """STRIDE-category alert distribution from zta.siem_alerts (proposed
    framework's live SIEM correlation). Joined to framework_comparison rather
    than timestamp-filtered, so a container restart can't replay leftover
    alerts from a prior run."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT sa.stride, COUNT(*) as c
            FROM zta.siem_alerts sa
            JOIN zta.framework_comparison fc
              ON fc.session_id = sa.session_id AND fc.framework_type = 'proposed'
            WHERE fc.comparison_id = %s
            GROUP BY sa.stride
        """, (run_id,))
        counts = {r["stride"]: r["c"] for r in cur.fetchall()}
    return counts


def stride_severity_distribution(conn, run_id):
    """STRIDE category x severity breakdown, for the Figure 4.4 severity panel."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT sa.stride, sa.severity, COUNT(*) as c
            FROM zta.siem_alerts sa
            JOIN zta.framework_comparison fc
              ON fc.session_id = sa.session_id AND fc.framework_type = 'proposed'
            WHERE fc.comparison_id = %s
            GROUP BY sa.stride, sa.severity
        """, (run_id,))
        rows = cur.fetchall()
    out = {}
    for r in rows:
        out.setdefault(r["stride"], {})[r["severity"]] = r["c"]
    return out


def label_to_stride(label):
    """Maps a ground-truth label to a STRIDE category, mirroring
    services/validation/app/main.py's compute_reasons() mapping."""
    L = (label or "BENIGN").upper()
    if L == "BENIGN":
        return None
    if "SPOOFING_INJECTED" in L:
        return "Spoofing"
    if "HEARTBLEED" in L:
        return "Tampering"
    if "REPUDIATION" in L:
        return "Repudiation"
    if "EXFILTRATION" in L:
        return "InformationDisclosure"
    # Real CIC-IDS2018 labels are "DoS attacks-GoldenEye"/"DoS attacks-Slowloris"
    # (space, not hyphen) — startswith("DOS") is what actually matches those;
    # DDOS is kept for any future file that adds DDoS-labelled rows (none of
    # the four files currently used do).
    if "DDOS" in L or L.startswith("DOS"):
        return "DoS"
    if "XSS" in L or "SQL INJECTION" in L or "WEB ATTACK" in L or ("BRUTE FORCE" in L and "WEB" in L):
        return "EoP"
    if "FTP-BRUTEFORCE" in L or "SSH-BRUTEFORCE" in L or "BRUTEFORCE" in L:
        return "Spoofing"  # credential-attack -> spoofing
    if "BOT" in L or "INFILTERATION" in L or "INFILTRATION" in L:
        return "InformationDisclosure"
    return "Other"


def security_accuracy_by_stride(conn, run_id):
    """Per-STRIDE-category detection rate (TPR) per framework."""
    out = {}
    with conn.cursor() as cur:
        for fw in FRAMEWORKS:
            cur.execute("""
                SELECT sc.original_label, fc.decision
                FROM zta.security_classifications sc
                JOIN zta.framework_comparison fc
                  ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
                WHERE sc.framework_type = %s AND fc.comparison_id = %s
            """, (fw, run_id))
            rows = cur.fetchall()
            by_cat = {}
            for r in rows:
                cat = label_to_stride(r["original_label"])
                if cat is None:
                    continue
                d = by_cat.setdefault(cat, {"n": 0, "detected": 0})
                d["n"] += 1
                if r["decision"] in ("step_up", "deny"):
                    d["detected"] += 1
            out[fw] = {
                cat: {**d, "tpr": round(d["detected"] / max(1, d["n"]), 4)}
                for cat, d in by_cat.items()
            }
    return out


def mcnemar_significance(conn, run_id):
    """McNemar's test (chi-square with continuity correction) comparing the
    proposed framework's paired correct/incorrect predictions against each
    baseline on the same sessions."""
    from scipy.stats import chi2

    with conn.cursor() as cur:
        cur.execute("""
            SELECT sc.session_id, sc.framework_type, sc.original_label, fc.decision
            FROM zta.security_classifications sc
            JOIN zta.framework_comparison fc
              ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
            WHERE sc.framework_type = ANY(%s) AND fc.comparison_id = %s
        """, (FRAMEWORKS, run_id))
        rows = cur.fetchall()

    # session_id -> {framework: correct(bool)}
    by_session = {}
    for r in rows:
        is_malicious = (r["original_label"] or "BENIGN").upper() != "BENIGN"
        predicted_malicious = r["decision"] in ("step_up", "deny")
        correct = (is_malicious == predicted_malicious)
        by_session.setdefault(r["session_id"], {})[r["framework_type"]] = correct

    out = {}
    for baseline in [fw for fw in FRAMEWORKS if fw != "proposed"]:
        b = c = both_correct = both_wrong = 0
        for fw_correct in by_session.values():
            if "proposed" not in fw_correct or baseline not in fw_correct:
                continue
            p_ok, base_ok = fw_correct["proposed"], fw_correct[baseline]
            if p_ok and not base_ok:
                b += 1
            elif not p_ok and base_ok:
                c += 1
            elif p_ok and base_ok:
                both_correct += 1
            else:
                both_wrong += 1

        n_pairs = b + c + both_correct + both_wrong
        if b + c == 0:
            statistic, p_value = 0.0, 1.0
        else:
            statistic = (abs(b - c) - 1) ** 2 / (b + c)
            p_value = chi2.sf(statistic, df=1)

        out[baseline] = {
            "n_paired_sessions": n_pairs,
            "proposed_correct_baseline_wrong": b,
            "proposed_wrong_baseline_correct": c,
            "both_correct": both_correct,
            "both_wrong": both_wrong,
            "mcnemar_chi2": round(statistic, 4),
            "p_value": round(p_value, 6),
            "significant_at_0.05": bool(p_value < 0.05),
        }
    return out


def main():
    conn = _connect()
    try:
        run_id = resolve_run_id(conn)
        result = {
            "comparison_id": run_id,
            "latency": latency_stats(conn, run_id),
            "decisions": decision_distribution(conn, run_id),
            "usability_benign_only": usability_benign_only(conn, run_id),
            "security_accuracy": security_accuracy(conn, run_id),
            "security_accuracy_by_stride": security_accuracy_by_stride(conn, run_id),
            "mcnemar_significance": mcnemar_significance(conn, run_id),
            "stride_alert_distribution": stride_distribution(conn, run_id),
            "stride_severity_distribution": stride_severity_distribution(conn, run_id),
        }

        # Network-condition results are a separate experiment with its own run provenance.
        result["network_conditions"] = None

        out_path = os.path.join(os.path.dirname(__file__), "chapter4_metrics.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

        print(json.dumps(result, indent=2))
        print(f"\nWritten to {out_path}")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
