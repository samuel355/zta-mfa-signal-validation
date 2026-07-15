#!/usr/bin/env python3
"""
Generate Chapter 4 figures from real, measured simulation data.

Reads scripts/chapter4_metrics.json (produced by scripts/compute_chapter4_metrics.py,
which queries the live comparison database). No hardcoded numbers — every value
in every figure traces back to a real decision made by a running service.

Frameworks: proposed, ablation, ahmadi2025, phani2025.
Jimmy (2025) excluded — its source publishes no risk-scoring formula, so it isn't
part of the head-to-head baseline re-implementation (see thesis 3.4.1).
"""

import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
METRICS_PATH = os.path.join(BASE_DIR, 'scripts', 'chapter4_metrics.json')
OUTPUT_DIR = os.path.join(BASE_DIR, 'updated', 'figures')

# Validated categorical palette (references/palette.md), fixed CVD-safe order —
# never reassigned or cycled per framework.
COLORS = {
    'proposed':   '#2a78d6',   # slot 1: blue
    'ablation':   '#1baf7a',   # slot 2: aqua
    'ahmadi2025': '#eda100',   # slot 3: yellow
    'phani2025':  '#008300',   # slot 4: green
}
LABELS = {
    'proposed':   'Proposed',
    'ablation':   'Ablation',
    'ahmadi2025': 'Ahmadi\n(2025)',
    'phani2025':  'Phani Kumar\nKanuri (2025)',
}
FRAMEWORKS = ['proposed', 'ablation', 'ahmadi2025', 'phani2025']

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.titleweight': 'bold',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'figure.facecolor': 'white',
})


def load_metrics():
    with open(METRICS_PATH) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Figure 4.1 — Security Accuracy: TPR, FPR, F1 across all four frameworks
# ---------------------------------------------------------------------------
def fig41(metrics):
    acc = metrics['security_accuracy']
    fig, axes = plt.subplots(1, 3, figsize=(14, 5.5))
    fig.suptitle(
        'Figure 4.1: Security Accuracy Metrics — Proposed Framework vs Ablation and Published Baselines\n'
        '(measured on live simulation data, CIC-IDS2018)',
        fontsize=12, fontweight='bold', y=1.03
    )

    labels = [LABELS[fw] for fw in FRAMEWORKS]
    colors = [COLORS[fw] for fw in FRAMEWORKS]
    x = np.arange(len(FRAMEWORKS))
    w = 0.55

    def bar_panel(ax, values, title, fmt='{:.1%}', ylim=(0, 1.15)):
        bars = ax.bar(x, values, width=w, color=colors, edgecolor='white', linewidth=0.8)
        ax.set_ylim(*ylim)
        if ylim[1] <= 1.2:
            ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
        ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8.5)
        ax.set_ylabel('Rate', fontsize=9)
        ax.set_title(title, fontsize=11, pad=8)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + ylim[1] * 0.01,
                    fmt.format(val), ha='center', va='bottom', fontsize=9, fontweight='bold')

    bar_panel(axes[0], [acc[fw]['tpr'] for fw in FRAMEWORKS], 'True Positive Rate (TPR)')
    bar_panel(axes[1], [acc[fw]['fpr'] for fw in FRAMEWORKS],
              'False Positive Rate (FPR)\n(lower is better)', ylim=(0, 0.55))
    bar_panel(axes[2], [acc[fw]['f1'] for fw in FRAMEWORKS], 'F1-Score', fmt='{:.3f}')
    n_decisions = acc[FRAMEWORKS[0]]['n']
    axes[2].text(0.5, -0.16,
                 f'n = {n_decisions:,} live decisions per framework. Ablation = proposed framework with the validation\n'
                 'layer removed. Jimmy (2025) excluded — no published formula (3.4.1).',
                 transform=axes[2].transAxes, fontsize=7, ha='center', color='grey', style='italic')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_4.1_Security_Accuracy_Metrics.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 4.2 — Performance: latency distribution + network condition sensitivity
# ---------------------------------------------------------------------------
def fig42(metrics):
    lat = metrics['latency']
    net = metrics['network_conditions']

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(16, 5.5))
    fig.suptitle(
        'Figure 4.2: Performance — Decision Latency Distribution and Network Condition Sensitivity',
        fontsize=12, fontweight='bold', y=1.03
    )

    # --- Panel 1: median + p95 latency per framework (log scale — proposed's
    # multi-hop chain is ~40x slower than the single-hop baselines) ---
    labels = [LABELS[fw] for fw in FRAMEWORKS]
    colors = [COLORS[fw] for fw in FRAMEWORKS]
    x = np.arange(len(FRAMEWORKS))
    medians = [lat[fw]['median_ms'] for fw in FRAMEWORKS]
    p95s = [lat[fw]['p95_ms'] for fw in FRAMEWORKS]

    w = 0.35
    ax1.bar(x - w/2, medians, width=w, color=colors, alpha=1.0, edgecolor='white', linewidth=0.8, label='Median')
    ax1.bar(x + w/2, p95s, width=w, color=colors, alpha=0.45, edgecolor='white', linewidth=0.8, label='p95')
    ax1.set_yscale('log')
    ax1.set_ylabel('Latency (ms, log scale)', fontsize=9)
    ax1.set_title('Decision Latency: Median vs p95', fontsize=11, pad=8)
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=8)
    for xi, mm, p in zip(x, medians, p95s):
        ax1.text(xi - w/2, mm * 1.15, f'{mm:.0f}', ha='center', fontsize=7.5, fontweight='bold')
        ax1.text(xi + w/2, p * 1.15, f'{p:.0f}', ha='center', fontsize=7.5, fontweight='bold')
    ax1.legend(fontsize=8, frameon=False, loc='upper left')
    ax1.text(0.5, -0.15, 'Proposed chains validation→gateway→trust (3 services);\nbaselines are single-hop.',
              transform=ax1.transAxes, fontsize=7, ha='center', color='grey', style='italic')

    # --- Panel 2: network condition latency (proposed framework only) ---
    conditions = ['normal', 'constrained', 'degraded']
    cond_labels = [net[c]['label'].replace(' (', '\n(') for c in conditions]
    cond_latency = [net[c]['avg_latency_ms'] for c in conditions]
    xr = np.arange(len(conditions))
    bars2 = ax2.bar(xr, cond_latency, width=0.5, color=COLORS['proposed'], edgecolor='white', linewidth=0.8)
    ax2.set_ylabel('Avg. Latency (ms)', fontsize=9)
    ax2.set_title('Proposed Framework Under\nSimulated Network Conditions', fontsize=11, pad=8)
    ax2.set_xticks(xr); ax2.set_xticklabels(cond_labels, fontsize=8)
    for bar, val in zip(bars2, cond_latency):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(cond_latency) * 0.02,
                  f'{val:.0f} ms', ha='center', va='bottom', fontsize=9, fontweight='bold', color=COLORS['proposed'])
    ax2.set_ylim(0, max(cond_latency) * 1.25)

    # --- Panel 3: TPR under the same network conditions (separate axis — no
    # dual-axis overlay; two measures of different scale get two panels) ---
    cond_tpr = [net[c]['tpr'] for c in conditions]
    bars3 = ax3.bar(xr, cond_tpr, width=0.5, color=COLORS['proposed'], alpha=0.7, edgecolor='white', linewidth=0.8)
    ax3.set_ylim(0, 1.0)
    ax3.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax3.set_ylabel('TPR', fontsize=9)
    ax3.set_title('Detection Accuracy Under the\nSame Network Conditions', fontsize=11, pad=8)
    ax3.set_xticks(xr); ax3.set_xticklabels(cond_labels, fontsize=8)
    for bar, val in zip(bars3, cond_tpr):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                  f'{val:.1%}', ha='center', va='bottom', fontsize=9, fontweight='bold', color=COLORS['proposed'])
    ax3.text(0.5, -0.15, f'n = {net["normal"]["samples"]} per condition, real artificial-delay injection (3.7).',
              transform=ax3.transAxes, fontsize=7, ha='center', color='grey', style='italic')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_4.2_Performance_Latency_Network_Conditions.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 4.3 — Usability: step-up rate and what it costs vs what it catches
# ---------------------------------------------------------------------------
def fig43(metrics):
    dec = metrics['decisions']
    acc = metrics['security_accuracy']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5))
    fig.suptitle(
        'Figure 4.3: Usability — Step-up Challenge Rate vs Detection Justification',
        fontsize=12, fontweight='bold', y=1.03
    )

    labels = [LABELS[fw] for fw in FRAMEWORKS]
    colors = [COLORS[fw] for fw in FRAMEWORKS]
    x = np.arange(len(FRAMEWORKS))

    # --- Left: step-up challenge rate per framework ---
    stepup = [dec[fw]['step_up_rate_pct'] for fw in FRAMEWORKS]
    bars = ax1.bar(x, stepup, width=0.55, color=colors, edgecolor='white', linewidth=0.8)
    ax1.set_ylabel('Step-up Challenge Rate (%)', fontsize=9)
    ax1.set_title('Step-up Challenge Rate', fontsize=11, pad=8)
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=8.5)
    ax1.set_ylim(0, max(stepup) * 1.2)
    for bar, val in zip(bars, stepup):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                  f'{val:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax1.text(0.5, -0.16,
              'A higher rate is not automatically worse — see right panel:\n'
              'proposed challenges more sessions, but every challenge is justified.',
              transform=ax1.transAxes, fontsize=7.5, ha='center', color='grey', style='italic')

    # --- Right: TPR (threats caught) vs FPR (false alarms) — shows whether a
    # framework's step-ups are "earned" ---
    w2 = 0.35
    tpr_vals = [acc[fw]['tpr'] for fw in FRAMEWORKS]
    fpr_vals = [acc[fw]['fpr'] for fw in FRAMEWORKS]
    ax2.bar(x - w2/2, tpr_vals, width=w2, color=colors, alpha=1.0, edgecolor='white', linewidth=0.8, label='TPR (threats caught)')
    ax2.bar(x + w2/2, fpr_vals, width=w2, color=colors, alpha=0.35, edgecolor='white', linewidth=0.8, label='FPR (false alarms)')
    ax2.set_ylim(0, 1.05)
    ax2.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax2.set_ylabel('Rate', fontsize=9)
    ax2.set_title('Step-ups Justified: TPR vs FPR', fontsize=11, pad=8)
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=8.5)
    for xi, t, fp in zip(x, tpr_vals, fpr_vals):
        ax2.text(xi - w2/2, t + 0.02, f'{t:.0%}', ha='center', fontsize=8, fontweight='bold')
        ax2.text(xi + w2/2, fp + 0.02, f'{fp:.0%}', ha='center', fontsize=8, fontweight='bold')
    ax2.legend(fontsize=8, frameon=False, loc='upper left', bbox_to_anchor=(0.0, 0.92))

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_4.3_Usability_StepUp_Rate.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 4.4 — SIEM Integration: STRIDE-mapped alert distribution and severity
# ---------------------------------------------------------------------------
def fig44(metrics):
    stride_dist = metrics['stride_alert_distribution']
    stride_sev = metrics['stride_severity_distribution']

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.suptitle(
        'Figure 4.4: SIEM Integration — STRIDE-Mapped Alert Distribution and Severity Breakdown\n'
        '(live SIEM correlation on the proposed framework)',
        fontsize=12, fontweight='bold', y=1.03
    )

    stride_order = ['Spoofing', 'Tampering', 'Repudiation', 'InformationDisclosure', 'DoS', 'EoP']
    stride_display = ['Spoofing', 'Tampering', 'Repudiation', 'Information\nDisclosure', 'Denial of\nService', 'Elevation\nof Privilege']
    palette6 = ['#2a78d6', '#1baf7a', '#eda100', '#008300', '#4a3aa7', '#e34948']  # slots 1-6, fixed order

    # --- Left: STRIDE alert distribution ---
    counts = [stride_dist.get(s, 0) for s in stride_order]
    bars = ax1.bar(stride_display, counts, color=palette6, edgecolor='white', linewidth=0.8, width=0.6)
    ax1.set_ylabel('Alert Count', fontsize=9)
    ax1.set_title('STRIDE-Mapped Alert Distribution\n(CIC-IDS2018 live simulation)', fontsize=11, pad=8)
    ax1.set_ylim(0, max(counts) * 1.15)
    for bar, val in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts) * 0.015,
                  str(val), ha='center', va='bottom', fontsize=9, fontweight='bold')
    ax1.tick_params(axis='x', labelsize=8)

    # --- Right: severity breakdown per STRIDE category (stacked) ---
    severities = ['low', 'medium', 'high']
    sev_colors = {'low': '#9ec5f4', 'medium': '#eda100', 'high': '#e34948'}
    bottom = np.zeros(len(stride_order))
    x2 = np.arange(len(stride_order))
    for sev in severities:
        vals = np.array([stride_sev.get(s, {}).get(sev, 0) for s in stride_order])
        ax2.bar(x2, vals, bottom=bottom, width=0.6, color=sev_colors[sev],
                edgecolor='white', linewidth=0.8, label=sev.capitalize())
        bottom += vals
    ax2.set_ylabel('Alert Count', fontsize=9)
    ax2.set_title('Severity Breakdown by STRIDE Category', fontsize=11, pad=8)
    ax2.set_xticks(x2); ax2.set_xticklabels(stride_display, fontsize=8)
    ax2.legend(fontsize=8.5, frameon=False, loc='upper right', title='Severity')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_4.4_STRIDE_Alert_Distribution_Severity.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 4.5 — Detection rate (TPR) per STRIDE category per framework
# ---------------------------------------------------------------------------
def fig45(metrics):
    by_stride = metrics.get('security_accuracy_by_stride')
    if not by_stride:
        return

    stride_order = ['Spoofing', 'Tampering', 'Repudiation', 'InformationDisclosure', 'DoS', 'EoP']
    stride_display = ['Spoofing', 'Tampering', 'Repudiation', 'Information\nDisclosure', 'Denial of\nService', 'Elevation\nof Privilege']

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.suptitle(
        'Figure 4.5: Detection Rate (TPR) by STRIDE Category — Why Aggregate TPR Differs\n'
        '(measured on live simulation data, CIC-IDS2018)',
        fontsize=12, fontweight='bold', y=1.03
    )

    n_fw = len(FRAMEWORKS)
    w = 0.8 / n_fw
    x = np.arange(len(stride_order))

    for i, fw in enumerate(FRAMEWORKS):
        cats = by_stride.get(fw, {})
        vals = [cats.get(s, {}).get('tpr', 0.0) for s in stride_order]
        offset = (i - (n_fw - 1) / 2) * w
        bars = ax.bar(x + offset, vals, width=w, color=COLORS[fw], edgecolor='white',
                      linewidth=0.6, label=LABELS[fw].replace('\n', ' '))
        for bar, val in zip(bars, vals):
            if val > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.015,
                        f'{val:.0%}', ha='center', va='bottom', fontsize=6.5, rotation=90)

    ax.set_xticks(x); ax.set_xticklabels(stride_display, fontsize=9)
    ax.set_ylabel('True Positive Rate (detection rate)', fontsize=9)
    ax.set_ylim(0, 1.18)
    ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
    ax.legend(fontsize=8.5, frameon=False, loc='upper right', ncol=2)

    ax.text(0.5, -0.14,
            'Baselines cluster detection almost entirely in Spoofing (the one category their published\n'
            'equations can observe via GPS/device signals) — network-layer categories (DoS, Tampering, EoP,\n'
            'Information Disclosure) fall outside either baseline\'s signal scope by construction.',
            transform=ax.transAxes, fontsize=7.5, ha='center', color='grey', style='italic')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_4.5_Detection_Rate_by_STRIDE_Category.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    m = load_metrics()
    fig41(m)
    fig42(m)
    fig43(m)
    fig44(m)
    fig45(m)
