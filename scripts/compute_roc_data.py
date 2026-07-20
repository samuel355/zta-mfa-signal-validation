#!/usr/bin/env python3
"""
Compute ROC curves and F1-vs-threshold curves for the proposed framework and
the two baselines with published equations, from live risk_score +
ground-truth-label data. Neither baseline paper publishes numeric threshold
values, so their chosen DENY_T/STEPUP_T are this study's own calibration,
shown against each baseline's own measured ROC curve.

Writes scripts/roc_data.json:
{"<framework>": {"points": [...], "auc": ..., "chosen_thresholds": {...}}, ...}
"""
import json
import os

import psycopg2
import psycopg2.extras

DSN = os.environ["DB_DSN"]  # no hardcoded fallback — set via compose/.env, never commit real credentials

RUN_ID = os.environ.get("METRICS_COMPARISON_ID")

# Chosen operating-point thresholds per framework, so each figure can mark
# where the actual deployed cutoff sits on its own ROC curve.
CHOSEN_THRESHOLDS = {
    "proposed":   {"allow_t": 0.24, "deny_t": 0.75},
    "ahmadi2025": {"stepup_t": 0.30, "deny_t": 0.70},
    "phani2025":  {"stepup_t": 0.50, "deny_t": 0.55},
}


def compute_for_framework(cur, framework, run_id):
    cur.execute("""
        SELECT sc.original_label, fc.risk_score
        FROM zta.security_classifications sc
        JOIN zta.framework_comparison fc
          ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
        WHERE sc.framework_type = %s AND fc.comparison_id = %s
    """, (framework, run_id))
    rows = cur.fetchall()

    malicious = sorted(float(r["risk_score"]) for r in rows if (r["original_label"] or "BENIGN").upper() != "BENIGN")
    benign = sorted(float(r["risk_score"]) for r in rows if (r["original_label"] or "BENIGN").upper() == "BENIGN")

    print(f"[{framework}] n_malicious={len(malicious)}  n_benign={len(benign)}")
    if not malicious or not benign:
        print(f"[{framework}] insufficient data, skipping")
        return None

    thresholds = [round(t / 1000.0, 3) for t in range(0, 1001)]
    points = []
    for t in thresholds:
        tp = sum(1 for s in malicious if s >= t)
        fn = len(malicious) - tp
        fp = sum(1 for s in benign if s >= t)
        tn = len(benign) - fp
        tpr = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        precision = tp / max(1, tp + fp)
        f1 = 2 * precision * tpr / max(1e-9, precision + tpr)
        points.append({"threshold": t, "tpr": round(tpr, 4), "fpr": round(fpr, 4), "f1": round(f1, 4)})

    # Exact rank-based AUC (Mann-Whitney interpretation), with average ranks
    # for tied risk scores. This avoids quantization error from the plotted
    # threshold grid and measures the probability that a random malicious
    # session receives a higher score than a random benign session.
    ranked = sorted([(s, 1) for s in malicious] + [(s, 0) for s in benign])
    positive_rank_sum = 0.0
    i = 0
    while i < len(ranked):
        j = i + 1
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        average_rank = ((i + 1) + j) / 2.0
        positive_rank_sum += average_rank * sum(label for _, label in ranked[i:j])
        i = j
    auc = (
        positive_rank_sum - len(malicious) * (len(malicious) + 1) / 2.0
    ) / (len(malicious) * len(benign))

    best = max(points, key=lambda p: p["f1"])
    return {
        "points": points,
        "auc": round(auc, 4),
        "n_malicious": len(malicious),
        "n_benign": len(benign),
        "best_f1_threshold": best["threshold"],
        "best_f1": best["f1"],
        "chosen_thresholds": CHOSEN_THRESHOLDS.get(framework, {}),
    }


def main():
    conn = psycopg2.connect(DSN, connect_timeout=15, cursor_factory=psycopg2.extras.RealDictCursor)
    cur = conn.cursor()

    run_id = RUN_ID
    if not run_id:
        cur.execute("""
            SELECT comparison_id
            FROM zta.framework_comparison
            WHERE framework_type = ANY(%s)
            GROUP BY comparison_id
            HAVING COUNT(DISTINCT framework_type) = 4
            ORDER BY MAX(created_at) DESC
            LIMIT 1
        """, (["proposed", "ablation", "ahmadi2025", "phani2025"],))
        row = cur.fetchone()
        if not row:
            raise RuntimeError("No complete four-framework experiment found")
        run_id = row["comparison_id"]

    result = {}
    for framework in ["proposed", "ahmadi2025", "phani2025"]:
        data = compute_for_framework(cur, framework, run_id)
        if data:
            result[framework] = data

    conn.close()

    out_path = os.path.join(os.path.dirname(__file__), "roc_data.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    for fw, d in result.items():
        print(f"[{fw}] AUC={d['auc']:.4f}  best_f1_threshold={d['best_f1_threshold']}  best_f1={d['best_f1']:.4f}")
    print(f"Written to {out_path}")


if __name__ == "__main__":
    main()
