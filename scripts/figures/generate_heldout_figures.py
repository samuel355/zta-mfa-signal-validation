#!/usr/bin/env python3
"""Build publication figures from the source-disjoint held-out evaluation."""
import json
import math
import shutil
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np


ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "results" / "freshheldout-report-20261027"
CUE = ROOT / "results" / "freshheldout-cue-20261027" / "cue-degraded-outcomes.jsonl"
THRESHOLDS = ROOT / "results" / "freshheldout-data" / "thresholds-shared.json"
OUTPUT = ROOT / "Figures" / "Fresh_Heldout_20261027"
SOURCE_FIGURES = ROOT / "Figures"

FRAMEWORKS = ("proposed", "ablation", "ahmadi2025", "phani2025")
COLORS = {
    "proposed": "#2a78d6",
    "ablation": "#1baf7a",
    "ahmadi2025": "#eda100",
    "phani2025": "#008300",
}
LABELS = {
    "proposed": "Proposed",
    "ablation": "Validation-disabled ablation",
    "ahmadi2025": "Ahmadi local implementation",
    "phani2025": "Phani/Kanuri local implementation",
}
BUCKET_LABELS = {
    "dos": "DoS",
    "eop": "Elevation of Privilege",
    "exfil": "Exfiltration",
    "rep": "Repudiation",
    "spoof": "Spoofing",
    "tls": "Tampering",
}
DECISIONS = ("allow", "step_up", "deny")
DECISION_LABELS = {"allow": "Allow", "step_up": "Step-up", "deny": "Deny"}
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 9,
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "figure.facecolor": "white",
})


def read_json(path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def read_jsonl(path):
    with path.open(encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    if not rows:
        raise ValueError(f"Empty input: {path}")
    return rows


def validate_rows(rows, path, expected_count):
    if len(rows) != expected_count:
        raise ValueError(f"{path}: expected {expected_count} rows, found {len(rows)}")
    hashes = [row.get("source_hash") for row in rows]
    if not all(hashes) or len(set(hashes)) != len(hashes):
        raise ValueError(f"{path}: missing or duplicate source hashes")
    for row in rows:
        if set(row.get("frameworks", {})) != set(FRAMEWORKS):
            raise ValueError(f"{path}: incomplete framework outcomes")


def save(fig, filename):
    fig.savefig(OUTPUT / filename, dpi=300, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def labels_and_colors():
    return [LABELS[fw] for fw in FRAMEWORKS], [COLORS[fw] for fw in FRAMEWORKS]


def positive(row, framework):
    return row["frameworks"][framework]["decision"] in {"step_up", "deny"}


def metrics(rows, framework, threshold=None):
    tp = fp = tn = fn = 0
    for row in rows:
        is_malicious = str(row.get("label", "BENIGN")).upper() != "BENIGN"
        result = row["frameworks"][framework]
        predicted = (
            float(result["risk_score"]) >= threshold
            if threshold is not None
            else positive(row, framework)
        )
        if is_malicious and predicted:
            tp += 1
        elif is_malicious:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    tpr = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    precision = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "tpr": tpr, "fpr": fpr, "f1": f1}


def auc_from_scores(rows, framework):
    positives = [
        float(row["frameworks"][framework]["risk_score"])
        for row in rows if str(row.get("label", "BENIGN")).upper() != "BENIGN"
    ]
    negatives = [
        float(row["frameworks"][framework]["risk_score"])
        for row in rows if str(row.get("label", "BENIGN")).upper() == "BENIGN"
    ]
    wins = sum(
        1.0 if positive > negative else 0.5 if positive == negative else 0.0
        for positive in positives for negative in negatives
    )
    return wins / (len(positives) * len(negatives))


def score_curve(rows, framework, selected_threshold):
    scores = [float(row["frameworks"][framework]["risk_score"]) for row in rows]
    thresholds = sorted(set(scores) | {selected_threshold, 0.0, math.nextafter(1.0, math.inf)}, reverse=True)
    points = [metrics(rows, framework, threshold) for threshold in thresholds]
    auc = float(np.trapezoid(
        [point["tpr"] for point in points],
        [point["fpr"] for point in points],
    ))
    return thresholds, points, auc


def fig_reporting_roc(rows, thresholds, expected):
    threshold_key = {
        "proposed": "ALLOW_T",
        "ablation": "ALLOW_T",
        "ahmadi2025": "AHMADI_ALLOW_T",
        "phani2025": "PHANI_ALLOW_T",
    }
    for framework in FRAMEWORKS:
        selected = float(thresholds["environment"][threshold_key[framework]])
        xs, points, auc = score_curve(rows, framework, selected)
        if not math.isclose(auc, expected[framework]["auc"], abs_tol=1e-10):
            raise ValueError(f"Held-out {framework} AUC does not match validated summary")
        chosen_index = min(range(len(xs)), key=lambda index: abs(xs[index] - selected))
        chosen = points[chosen_index]
        color = COLORS[framework]

        order = np.argsort(xs)[::-1]
        roc_fpr = [points[index]["fpr"] for index in order]
        roc_tpr = [points[index]["tpr"] for index in order]
        fig, ax = plt.subplots(figsize=(6.3, 5.5))
        ax.plot(roc_fpr, roc_tpr, color=color, linewidth=2, label=f"AUC = {auc:.3f}")
        ax.plot([0, 1], [0, 1], linestyle="--", color="#999999", linewidth=1, label="Chance")
        ax.scatter([chosen["fpr"]], [chosen["tpr"]], color="#e34948", zorder=4)
        ax.annotate(
            f"Frozen threshold = {selected:.6f}\n"
            f"Held-out TPR {chosen['tpr']:.1%}, FPR {chosen['fpr']:.1%}",
            xy=(chosen["fpr"], chosen["tpr"]), xytext=(0.43, 0.28),
            textcoords="axes fraction", fontsize=8,
            arrowprops={"arrowstyle": "->", "color": "#e34948"},
        )
        ax.set(xlim=(-0.02, 1.02), ylim=(-0.02, 1.02),
               xlabel="False positive rate", ylabel="True positive rate")
        ax.xaxis.set_major_formatter(mticker.PercentFormatter(1))
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
        ax.set_aspect("equal")
        ax.set_title(f"Held-out ROC — {LABELS[framework]}")
        ax.legend(frameon=False, loc="lower right")
        ax.text(
            0.5, -0.18,
            "Held-out reporting partition (n=800); the marked operating threshold was frozen using calibration data.",
            transform=ax.transAxes, ha="center", color="#666666", fontsize=7.5,
        )
        fig.tight_layout()
        save(fig, f"Heldout_ROC_{framework}.png")


def fig_reporting_metrics(rows, expected):
    calculated = {fw: metrics(rows, fw) for fw in FRAMEWORKS}
    for fw in FRAMEWORKS:
        calculated[fw]["auc"] = auc_from_scores(rows, fw)
        for key in ("tpr", "fpr", "f1", "auc"):
            if not math.isclose(calculated[fw][key], expected[fw][key], abs_tol=1e-10):
                raise ValueError(f"Reporting {fw} {key} does not match validated summary")
    names, colors = labels_and_colors()
    measures = (("tpr", "TPR"), ("fpr", "FPR"), ("f1", "F1-score"), ("auc", "ROC AUC"))
    fig, axes = plt.subplots(1, 4, figsize=(16.5, 4.8))
    for ax, (key, title) in zip(axes, measures):
        values = [calculated[fw][key] for fw in FRAMEWORKS]
        bars = ax.bar(range(len(FRAMEWORKS)), values, color=colors, width=0.65)
        ax.set_ylim(0, 0.10 if key == "fpr" else 1.12)
        if key in {"tpr", "fpr"}:
            ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
        ax.set_xticks(range(len(FRAMEWORKS)), names, rotation=25, ha="right", fontsize=7)
        ax.set_title(title)
        for bar, value in zip(bars, values):
            label = f"{value:.1%}" if key in {"tpr", "fpr"} else f"{value:.4f}"
            offset = 0.002 if key == "fpr" else 0.025
            ax.text(bar.get_x() + bar.get_width()/2, value + offset, label, ha="center", fontsize=8)
    fig.suptitle("Held-out reporting performance (n=800; 542 malicious, 258 benign)")
    fig.tight_layout()
    save(fig, "Reporting_Performance.png")


def fig_coverage(coverage):
    frameworks = list(FRAMEWORKS)
    names, colors = labels_and_colors()
    visible = [coverage["frameworks"][fw]["visible_tpr"] for fw in frameworks]
    full = [coverage["frameworks"][fw]["all_malicious_tpr"] for fw in frameworks]
    x = np.arange(len(frameworks))
    width = 0.34
    fig, ax = plt.subplots(figsize=(9.2, 5))
    first = ax.bar(x - width/2, visible, width, color=colors, label=f"Comparator-readable slice (n={coverage['n_visible']})")
    second = ax.bar(x + width/2, full, width, color=colors, alpha=0.48, label="All malicious reporting cases (n=542)")
    for bars in (first, second):
        for bar in bars:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.018, f"{bar.get_height():.1%}",
                    ha="center", fontsize=7.5)
    ax.set_ylim(0, 1.15)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
    ax.set_xticks(x, names, rotation=18, ha="right", fontsize=7.5)
    ax.set_ylabel("True positive rate")
    ax.set_title("Comparator signal-visibility diagnostic")
    ax.legend(frameon=False, fontsize=8)
    ax.text(
        0.5, -0.24,
        "Diagnostic subset: GPS deviation >100 km or adverse posture. Descriptive only; it is not a causal coverage estimate.",
        transform=ax.transAxes, ha="center", color="#666666", fontsize=7.5,
    )
    fig.tight_layout()
    save(fig, "Comparator_Visibility.png")


def bucket_of(row):
    return str(row.get("bucket", "unknown")).split(",", 1)[0].strip().lower()


def fig_stride(rows):
    buckets = [bucket for bucket in BUCKET_LABELS if any(bucket_of(row) == bucket for row in rows)]
    x = np.arange(len(buckets))
    width = 0.19
    fig, ax = plt.subplots(figsize=(13.5, 5.4))
    for i, framework in enumerate(FRAMEWORKS):
        values = []
        for bucket in buckets:
            members = [row for row in rows if bucket_of(row) == bucket and str(row.get("label", "BENIGN")).upper() != "BENIGN"]
            values.append(sum(positive(row, framework) for row in members) / len(members) if members else 0)
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, values, width, color=COLORS[framework], label=LABELS[framework])
        for bar, value in zip(bars, values):
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.02, f"{value:.0%}", ha="center", fontsize=6.5)
    counts = [
        sum(bucket_of(row) == bucket and str(row.get("label", "BENIGN")).upper() != "BENIGN" for row in rows)
        for bucket in buckets
    ]
    ax.set_xticks(x, [f"{BUCKET_LABELS[b]}\n(n={count})" for b, count in zip(buckets, counts)], fontsize=7.5)
    ax.set_ylim(0, 1.08)
    ax.set_yticks(np.linspace(0, 1, 6))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
    ax.set_ylabel("Detection rate (step-up or deny)")
    ax.set_title("Held-out detection by STRIDE-related workload group")
    ax.legend(frameon=False, fontsize=7.5, loc="upper left", bbox_to_anchor=(1.0, 1.0))
    fig.tight_layout()
    save(fig, "STRIDE_Detection.png")


def fig_cue_sensitivity(full_rows, degraded_rows):
    full_by_hash = {row["source_hash"]: row for row in full_rows}
    degraded_by_hash = {row["source_hash"]: row for row in degraded_rows}
    if full_by_hash.keys() != degraded_by_hash.keys():
        raise ValueError("Cue-ablation replay does not match the held-out source set")
    cue_buckets = ("dos", "eop", "exfil", "rep", "spoof", "tls")
    labels = {
        "dos": "DoS\n(network flow)",
        "eop": "EoP\n(network flow)",
        "exfil": "Exfiltration\n(telemetry)",
        "rep": "Repudiation\n(flag)",
        "spoof": "Spoofing\n(GPS)",
        "tls": "Tampering\n(TLS fingerprint)",
    }
    full_rates, degraded_rates, counts = [], [], []
    for bucket in cue_buckets:
        members = [r for r in full_rows if bucket_of(r) == bucket and str(r.get("label", "BENIGN")).upper() != "BENIGN"]
        replay = [degraded_by_hash[r["source_hash"]] for r in members]
        if not members or any(r.get("cue_removed") is None for r in replay):
            raise ValueError(f"Missing cue-degraded cases for {bucket}")
        counts.append(len(members))
        full_rates.append(sum(positive(r, "proposed") for r in members)/len(members))
        degraded_rates.append(sum(positive(r, "proposed") for r in replay)/len(replay))
    x = np.arange(len(cue_buckets))
    width = 0.36
    fig, ax = plt.subplots(figsize=(10.5, 5))
    b1 = ax.bar(x-width/2, full_rates, width, color=COLORS["proposed"], label="Original held-out inputs")
    b2 = ax.bar(x+width/2, degraded_rates, width, color="#e58e26", label="One input field removed")
    for bars in (b1, b2):
        for bar in bars:
            ax.text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.025, f"{bar.get_height():.1%}", ha="center", fontsize=7.5)
    ax.set_ylim(0, 1.18)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
    ax.set_xticks(x, [f"{labels[b]}\n(n={n})" for b, n in zip(cue_buckets, counts)], fontsize=7.5)
    ax.set_ylabel("Proposed detection rate")
    ax.set_title("Held-out sensitivity to single-field simulator-input ablation")
    ax.legend(frameon=False, fontsize=8)
    ax.text(
        0.5, -0.24,
        "Same 800 source-disjoint cases and frozen thresholds. Input ablation is not a realistic attack counterfactual.",
        transform=ax.transAxes, ha="center", color="#666666", fontsize=7.5,
    )
    fig.tight_layout()
    save(fig, "Cue_Field_Sensitivity.png")


def fig_risk_distribution(rows, thresholds):
    groups = [("Benign", [r for r in rows if str(r.get("label", "BENIGN")).upper() == "BENIGN"])]
    for bucket, name in BUCKET_LABELS.items():
        group = [r for r in rows if bucket_of(r) == bucket and str(r.get("label", "BENIGN")).upper() != "BENIGN"]
        if group:
            groups.append((name, group))
    values = [[float(row["frameworks"]["proposed"]["risk_score"]) for row in group] for _, group in groups]
    labels = [f"{name}\n(n={len(group)})" for name, group in groups]
    fig, ax = plt.subplots(figsize=(11, 5.5))
    box = ax.boxplot(values, patch_artist=True, showfliers=False, widths=0.58, medianprops={"color": "#222222"})
    for i, patch in enumerate(box["boxes"]):
        patch.set_facecolor("#9dbde5" if i == 0 else COLORS["proposed"])
        patch.set_alpha(0.65)
    allow = float(thresholds["environment"]["ALLOW_T"])
    deny = float(thresholds["environment"]["DENY_T"])
    ax.axhline(allow, color="#d89c00", linestyle="--", linewidth=1.2, label=f"Step-up boundary = {allow:.3f}")
    ax.axhline(deny, color="#c83b3b", linestyle="--", linewidth=1.2, label=f"Deny boundary = {deny:.6f}")
    ax.set_xticks(range(1, len(labels)+1), labels, fontsize=7.5)
    ax.set_ylim(0, 0.46)
    ax.set_ylabel("Proposed risk score")
    ax.set_title("Held-out risk-score distribution by workload group")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    save(fig, "Risk_Score_Distribution.png")


def fig_decisions(rows):
    names, _ = labels_and_colors()
    fig, ax = plt.subplots(figsize=(9, 5.2))
    y = np.arange(len(FRAMEWORKS))
    width = 0.22
    decision_colors = {"allow": "#a7c7a2", "step_up": "#f0c75e", "deny": "#d96b6b"}
    for decision in DECISIONS:
        counts = [sum(row["frameworks"][fw]["decision"] == decision for row in rows) for fw in FRAMEWORKS]
        offset = (DECISIONS.index(decision) - 1) * width
        bars = ax.barh(y + offset, counts, height=width, color=decision_colors[decision],
                       label=DECISION_LABELS[decision])
        for bar, count in zip(bars, counts):
            ax.text(count + 8, bar.get_y()+bar.get_height()/2, str(count), va="center", fontsize=8)
    ax.set_yticks(y, names, fontsize=7.5)
    ax.invert_yaxis()
    ax.set_xlim(0, 900)
    ax.set_xlabel("Reporting decisions (n=800)")
    ax.set_title("Held-out policy decision distribution")
    ax.legend(frameon=False, ncol=3, loc="lower right")
    fig.tight_layout()
    save(fig, "Policy_Decisions.png")


def fig_latency(summary):
    latencies = summary["latency_ms"]
    names, colors = labels_and_colors()
    metrics_to_plot = (("mean_ms", "Mean"), ("p95_ms", "p95"))
    x = np.arange(len(FRAMEWORKS))
    width = 0.34
    fig, ax = plt.subplots(figsize=(9, 5))
    for i, (key, label) in enumerate(metrics_to_plot):
        vals = [latencies[fw][key] for fw in FRAMEWORKS]
        bars = ax.bar(x + (i-0.5)*width, vals, width, color=colors, alpha=1 if i == 0 else 0.48, label=label)
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x()+bar.get_width()/2, val*1.04, f"{val:.1f}", ha="center", fontsize=7)
    ax.set_yscale("log")
    ax.set_xticks(x, names, rotation=17, ha="right", fontsize=7.5)
    ax.set_ylabel("End-to-end latency (ms; log scale)")
    ax.set_title("Held-out end-to-end decision latency")
    ax.legend(frameon=False)
    fig.tight_layout()
    save(fig, "End_to_End_Latency.png")


def fig_latency_components(summary):
    proposed = summary["latency_ms"]["proposed"]
    stages = proposed["stages"]
    labels = [
        "Classifier / reason",
        "Validation total (roll-up)",
        "Gateway total (roll-up)",
        "SIEM query",
        "Trust HTTP",
        "Enrichment",
        "Cross-source checks",
        "Quality scoring",
        "Trust engine",
        "Client/network/unattributed remainder",
    ]
    values = [
        stages["classifier_and_reason_ms"]["mean_ms"],
        stages["validation_total_ms"]["mean_ms"],
        stages["gateway_total_ms"]["mean_ms"],
        stages["siem_query_ms"]["mean_ms"],
        stages["trust_http_ms"]["mean_ms"],
        stages["enrichment_ms"]["mean_ms"],
        stages["cross_checks_ms"]["mean_ms"],
        stages["quality_scoring_ms"]["mean_ms"],
        stages["trust_engine_ms"]["mean_ms"],
        proposed["client_network_and_unattributed_ms"]["mean_ms"],
    ]
    order = np.argsort(values)
    fig, ax = plt.subplots(figsize=(9, 5.6))
    bars = ax.barh([labels[i] for i in order], [values[i] for i in order], color="#2a78d6")
    for bar, value in zip(bars, [values[i] for i in order]):
        ax.text(value + 2, bar.get_y()+bar.get_height()/2, f"{value:.3f} ms", va="center", fontsize=7.5)
    ax.set_xlabel("Mean time per reporting case (ms)")
    ax.set_title("Instrumented latency stages — proposed framework (n=800)")
    ax.text(
        0.5, -0.17,
        "Validation and gateway totals are roll-ups that overlap their component bars; do not sum these values. Remainder is not pure network time.",
        transform=ax.transAxes, ha="center", color="#666666", fontsize=7.5,
    )
    fig.tight_layout()
    save(fig, "Latency_Component_Breakdown.png")


def fig_friction(rows):
    fig, ax = plt.subplots(figsize=(7.2, 5.5))
    for framework in FRAMEWORKS:
        result = metrics(rows, framework)
        ax.scatter(result["fpr"], result["tpr"], s=85, color=COLORS[framework], label=LABELS[framework], zorder=3)
        ax.annotate(LABELS[framework], (result["fpr"], result["tpr"]), xytext=(7, 5),
                    textcoords="offset points", fontsize=7)
    ax.set(xlim=(-0.015, 0.12), ylim=(0, 1.08),
           xlabel="Benign sessions requiring step-up/deny (FPR)",
           ylabel="Malicious sessions detected (TPR)")
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(1))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(1))
    ax.set_title("Held-out detection vs benign-session friction")
    fig.tight_layout()
    save(fig, "Friction_vs_Detection.png")


def copy_static_diagrams():
    unchanged = {
        "1. Framework Architecture.jpg": "Framework_Architecture.jpg",
        "2. Context-signal-validation process.jpg": "Context_Signal_Validation_Process.jpg",
        "3. SIEM Feedback Loop.jpg": "SIEM_Feedback_Loop.jpg",
    }
    for source_name, target_name in unchanged.items():
        source = SOURCE_FIGURES / source_name
        if not source.is_file():
            raise FileNotFoundError(f"Missing unchanged diagram: {source}")
        shutil.copy2(source, OUTPUT / target_name)


def write_provenance():
    (OUTPUT / "PROVENANCE.txt").write_text(
        "Fresh held-out figure pack — 2026-10-27 run\n"
        "================================================\n"
        "Reporting metrics, score distributions, policy decisions, cue sensitivity,\n"
        "STRIDE groups, comparator visibility and latency use:\n"
        "  results/freshheldout-report-20261027/heldout-summary-validated.json\n"
        "  results/freshheldout-report-20261027/reporting-outcomes.jsonl\n"
        "  results/freshheldout-report-20261027/paired-and-coverage-summary.json\n"
        "  results/freshheldout-cue-20261027/cue-degraded-outcomes.jsonl\n"
        "Held-out ROC curves use reporting scores; annotated operating thresholds were\n"
        "frozen using the 1,200-case calibration partition in:\n"
        "  results/freshheldout-data/thresholds-shared.json\n"
        "AUCs are independently checked against heldout-summary-validated.json.\n"
        "The three architecture/process diagrams are unchanged copies from Figures/.\n"
        "No updated CPU, memory, throughput, or parameter-sweep measurements were\n"
        "available for this held-out run; those older-cohort plots are intentionally\n"
        "not copied into this fresh-evaluation pack.\n"
        "Cue-field ablations are simulator-input sensitivity analyses, not realistic\n"
        "attack counterfactuals. Comparator outcomes are local implementations only.\n",
        encoding="utf-8",
    )


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    reporting = read_jsonl(RESULTS / "reporting-outcomes.jsonl")
    cue = read_jsonl(CUE)
    validate_rows(reporting, "reporting outcomes", 800)
    validate_rows(cue, "cue-degraded outcomes", 800)

    summary = read_json(RESULTS / "heldout-summary-validated.json")
    paired = read_json(RESULTS / "paired-and-coverage-summary.json")
    thresholds = read_json(THRESHOLDS)
    expected_environment = summary["calibration_thresholds"]
    if thresholds["environment"]["DENY_T"] != expected_environment["DENY_T"]:
        raise ValueError("Shared threshold manifest and validated held-out summary disagree")

    threshold_key = {
        "proposed": "ALLOW_T",
        "ablation": "ALLOW_T",
        "ahmadi2025": "AHMADI_ALLOW_T",
        "phani2025": "PHANI_ALLOW_T",
    }
    for framework, key in threshold_key.items():
        if not math.isclose(
            float(thresholds["environment"][key]),
            float(summary["calibration_thresholds"][key]),
            abs_tol=1e-12,
        ):
            raise ValueError(f"Frozen {framework} threshold differs between manifests")

    for framework in FRAMEWORKS:
        for prefix in ("Calibration_ROC_", "Threshold_F1_"):
            stale = OUTPUT / f"{prefix}{framework}.png"
            if stale.exists():
                stale.unlink()

    copy_static_diagrams()
    fig_reporting_roc(reporting, thresholds, summary["reporting_metrics"])
    fig_reporting_metrics(reporting, summary["reporting_metrics"])
    fig_coverage(paired["comparator_readable_signal_slice"])
    fig_stride(reporting)
    fig_cue_sensitivity(reporting, cue)
    fig_risk_distribution(reporting, thresholds)
    fig_decisions(reporting)
    fig_latency(summary)
    fig_latency_components(summary)
    fig_friction(reporting)
    write_provenance()
    print(f"Generated figure pack: {OUTPUT}")
    print(f"PNG/JPG figures: {len(list(OUTPUT.glob('*.png'))) + len(list(OUTPUT.glob('*.jpg')))}")


if __name__ == "__main__":
    main()
