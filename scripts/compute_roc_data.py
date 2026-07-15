#!/usr/bin/env python3
"""
Compute real ROC curves and F1-vs-threshold curves for every framework (the
proposed framework plus the two baselines with published equations) from live
risk_score + ground-truth-label data. Replaces the previously fabricated
Figures 3.16/3.17 (the thesis's claimed "AUC=0.94, ROC analysis yielded
threshold=0.25" did not hold up against real data — see 3.5.6 note).

Extended to Ahmadi/Phani because neither source paper publishes numeric
threshold values (verified directly against Papers/*.pdf) — our chosen
DENY_T/STEPUP_T for each baseline are our own calibration. Showing each
baseline's operating point sitting at a defensible spot on its OWN measured
ROC curve (not just the proposed framework's) answers "why these specific
numbers" for every model in the comparison, not only ours.

Writes scripts/roc_data.json:
{"<framework>": {"points": [...], "auc": ..., "chosen_thresholds": {...}}, ...}
"""
import json
import os

import psycopg2
import psycopg2.extras

DSN = os.environ["DB_DSN"]  # no hardcoded fallback — set via compose/.env, never commit real credentials

# Chosen operating-point thresholds per framework, so each figure can mark
# where the actual deployed cutoff sits on its own ROC curve.
CHOSEN_THRESHOLDS = {
    "proposed":   {"allow_t": 0.30, "deny_t": 0.75},
    "ahmadi2025": {"stepup_t": 0.30, "deny_t": 0.70},
    "phani2025":  {"stepup_t": 0.50, "deny_t": 0.55},
}


def compute_for_framework(cur, framework):
    cur.execute("""
        SELECT sc.original_label, fc.risk_score
        FROM zta.security_classifications sc
        JOIN zta.framework_comparison fc
          ON fc.session_id = sc.session_id AND fc.framework_type = sc.framework_type
        WHERE sc.framework_type = %s
    """, (framework,))
    rows = cur.fetchall()

    malicious = sorted(float(r["risk_score"]) for r in rows if (r["original_label"] or "BENIGN").upper() != "BENIGN")
    benign = sorted(float(r["risk_score"]) for r in rows if (r["original_label"] or "BENIGN").upper() == "BENIGN")

    print(f"[{framework}] n_malicious={len(malicious)}  n_benign={len(benign)}")
    if not malicious or not benign:
        print(f"[{framework}] insufficient data, skipping")
        return None

    thresholds = [round(t * 0.02, 2) for t in range(0, 51)]  # 0.00 .. 1.00
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

    # AUC via trapezoidal rule over (fpr, tpr), traced by descending threshold —
    # the natural monotonic order (threshold=1.0 -> origin, decreasing threshold
    # only ever increases both fpr and tpr). Sorting by fpr directly breaks on
    # ties from coarse sample sets and can misorder the integration path.
    roc_sorted = sorted(points, key=lambda p: -p["threshold"])
    auc = 0.0
    for i in range(1, len(roc_sorted)):
        x0, x1 = roc_sorted[i - 1]["fpr"], roc_sorted[i]["fpr"]
        y0, y1 = roc_sorted[i - 1]["tpr"], roc_sorted[i]["tpr"]
        auc += (x1 - x0) * (y0 + y1) / 2.0

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

    result = {}
    for framework in ["proposed", "ahmadi2025", "phani2025"]:
        data = compute_for_framework(cur, framework)
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
