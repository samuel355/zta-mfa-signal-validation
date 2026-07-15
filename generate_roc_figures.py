#!/usr/bin/env python3
"""
Generate real ROC curve and F1-vs-threshold figures from scripts/roc_data.json
(produced by scripts/compute_roc_data.py against live risk_score + ground-truth
data), for the proposed framework AND the two baselines with published
equations (Ahmadi 2025, Phani 2025).

Neither baseline paper publishes numeric threshold values (verified against
Papers/*.pdf) — our chosen operating points are our own calibration. These
figures show each framework's chosen threshold sitting at a defensible point
on its OWN measured ROC curve, which is the strongest available defense for
"why these specific numbers" when a source paper gives none.
"""
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROC_DATA_PATH = os.path.join(BASE_DIR, 'scripts', 'roc_data.json')
OUTPUT_DIR = os.path.join(BASE_DIR, 'updated', 'figures')

# Consistent with the Chapter 4 categorical palette (proposed=blue, ahmadi2025=yellow, phani2025=green)
FRAMEWORK_COLOR = {
    'proposed':   '#2a78d6',
    'ahmadi2025': '#eda100',
    'phani2025':  '#008300',
}
FRAMEWORK_LABEL = {
    'proposed':   'Proposed Framework',
    'ahmadi2025': 'Ahmadi (2025) Baseline',
    'phani2025':  'Phani Kumar Kanuri (2025) Baseline',
}
# Figure numbering: 3.16/3.17 for the proposed framework (already referenced
# in thesis Methodology 3.5.6); 3.18-3.21 are new additions for the baselines'
# threshold justification, to be slotted into Chapter 3 or 4 as appropriate.
FIGURE_NUMBERS = {
    'proposed':   {'f1': '3.16', 'roc': '3.17'},
    'ahmadi2025': {'f1': '3.18', 'roc': '3.19'},
    'phani2025':  {'f1': '3.20', 'roc': '3.21'},
}

RED = '#e34948'
GREY = '#9a9a94'

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.titleweight': 'bold',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'figure.facecolor': 'white',
})


def load_data():
    with open(ROC_DATA_PATH) as f:
        return json.load(f)


def primary_threshold(chosen):
    """Pick the single threshold to annotate on the F1 chart — allow_t if present
    (proposed), else stepup_t (baselines, since that's their first enforcement gate)."""
    if 'allow_t' in chosen:
        return 'allow_t', chosen['allow_t']
    if 'stepup_t' in chosen:
        return 'stepup_t', chosen['stepup_t']
    return None, None


def fig_f1_vs_threshold(framework, data):
    points = data['points']
    thresholds = [p['threshold'] for p in points]
    f1s = [p['f1'] for p in points]
    chosen = data['chosen_thresholds']
    color = FRAMEWORK_COLOR[framework]
    label = FRAMEWORK_LABEL[framework]
    fignum = FIGURE_NUMBERS[framework]['f1']

    fig, ax = plt.subplots(figsize=(8, 5.5))
    fig.suptitle(f'Figure {fignum}: F1-Score vs Risk Threshold — {label}\n(measured on live simulation data)',
                 fontsize=12, fontweight='bold', y=1.02)

    ax.plot(thresholds, f1s, color=color, linewidth=2)
    ax.set_xlabel('Risk Threshold', fontsize=9)
    ax.set_ylabel('F1-Score', fontsize=9)
    ax.set_ylim(0, 1.05)
    ax.set_xlim(0, 1.0)

    name, t_val = primary_threshold(chosen)
    chosen_point = next((p for p in points if p['threshold'] == t_val), None) if t_val is not None else None
    if chosen_point:
        ax.axvline(t_val, color=RED, linestyle='--', linewidth=1.2, alpha=0.8)
        ax.plot(t_val, chosen_point['f1'], 'o', color=RED, markersize=8, zorder=5)
        ax.annotate(f'{name.upper()} = {t_val}\nF1 = {chosen_point["f1"]:.3f}\nTPR={chosen_point["tpr"]:.1%}, FPR={chosen_point["fpr"]:.1%}',
                    xy=(t_val, chosen_point['f1']), xytext=(min(0.75, t_val + 0.12), max(0.15, chosen_point['f1'] - 0.25)),
                    fontsize=8.5, color=RED,
                    arrowprops=dict(arrowstyle='->', color=RED, lw=1))

    threshold_note = ('Source paper publishes no numeric threshold' if framework != 'proposed'
                       else 'Thesis Ch.3.5.6 originally claimed threshold=0.25 without real ROC evidence')
    ax.text(0.5, -0.16,
            f'n_malicious={data["n_malicious"]}, n_benign={data["n_benign"]}. {threshold_note} —\n'
            f'operating point chosen empirically, not the pure F1-maximizing point ({data["best_f1_threshold"]}).',
            transform=ax.transAxes, fontsize=7.5, ha='center', color='grey', style='italic')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_{fignum}_F1_Score_vs_Risk_Threshold_{framework}.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


def fig_roc_curve(framework, data):
    # Sort by descending threshold — the natural, monotonic order to trace an ROC
    # curve (threshold=1.0 -> FPR=TPR=0, decreasing threshold only ever increases
    # both). Sorting by FPR directly breaks on ties and produces a jagged curve.
    points = sorted(data['points'], key=lambda p: -p['threshold'])
    fprs = [p['fpr'] for p in points]
    tprs = [p['tpr'] for p in points]
    auc = data['auc']
    chosen = data['chosen_thresholds']
    color = FRAMEWORK_COLOR[framework]
    label = FRAMEWORK_LABEL[framework]
    fignum = FIGURE_NUMBERS[framework]['roc']

    fig, ax = plt.subplots(figsize=(7, 6.5))
    fig.suptitle(f'Figure {fignum}: ROC Analysis — {label} Decision Thresholds\n(measured on live simulation data)',
                 fontsize=12, fontweight='bold', y=1.02)

    ax.plot(fprs, tprs, color=color, linewidth=2, label=f'{label} (AUC = {auc:.3f})')
    ax.plot([0, 1], [0, 1], color=GREY, linestyle='--', linewidth=1, label='Random classifier (AUC = 0.5)')
    ax.fill_between(fprs, tprs, alpha=0.08, color=color)

    markers = [('o', RED), ('s', '#4a3aa7')]
    # Fixed, well-separated label anchors (rather than offsets relative to each
    # point) — baseline operating points cluster tightly near the origin, so
    # relative offsets collided when two thresholds landed close together.
    label_anchors = [(0.42, 0.62), (0.42, 0.32)]
    for i, (name, t_val) in enumerate(chosen.items()):
        point = next((p for p in points if p['threshold'] == t_val), None)
        if not point:
            continue
        marker, mcolor = markers[i % len(markers)]
        anchor = label_anchors[i % len(label_anchors)]
        ax.plot(point['fpr'], point['tpr'], marker, color=mcolor, markersize=9, zorder=5)
        ax.annotate(f'{name.upper()}={t_val}\n(TPR={point["tpr"]:.1%}, FPR={point["fpr"]:.1%})',
                    xy=(point['fpr'], point['tpr']),
                    xytext=anchor,
                    fontsize=8, color=mcolor, arrowprops=dict(arrowstyle='->', color=mcolor, lw=1))

    ax.set_xlabel('False Positive Rate', fontsize=9)
    ax.set_ylabel('True Positive Rate', fontsize=9)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.xaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax.legend(fontsize=8.5, frameon=False, loc='lower right')
    ax.set_aspect('equal')

    threshold_note = ('Source paper publishes no numeric threshold.' if framework != 'proposed'
                       else 'Thesis Ch.3.5.6 originally claimed threshold=0.25 without real ROC evidence.')
    ax.text(0.5, -0.13, f'n_malicious={data["n_malicious"]}, n_benign={data["n_benign"]}. {threshold_note}',
            transform=ax.transAxes, fontsize=7.5, ha='center', color='grey', style='italic')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_{fignum}_ROC_Analysis_Decision_Thresholds_{framework}.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    all_data = load_data()
    for fw, d in all_data.items():
        fig_f1_vs_threshold(fw, d)
        fig_roc_curve(fw, d)
