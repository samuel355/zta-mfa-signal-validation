#!/usr/bin/env python3
"""
Generate Chapter 3 sensitivity-analysis figures from the real parameter sweep.

Reads scripts/sensitivity_sweep_results.json (produced by
scripts/sensitivity_sweep_penalties.py, which replays real collected signal
payloads from zta.validated_context through validation -> gateway at each
configuration). Replaces the earlier grid-search figures that visualized
optimization runs which never actually happened.

The sweep replays real signals against a freshly restarted validation
container per config, so it cannot reproduce the live SIEM alert state each
config saw during the original run — sweep baseline FPR therefore differs
slightly from the live full-run FPR reported in Chapter 4. Relative
differences across configs (what this figure is for) are unaffected.
"""
import json
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
import psycopg2
import psycopg2.extras

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SWEEP_PATH = os.path.join(BASE_DIR, 'scripts', 'sensitivity_sweep_results.json')
OUTPUT_DIR = os.path.join(BASE_DIR, 'updated', 'figures')

BLUE = '#2a78d6'
AQUA = '#1baf7a'
YELLOW = '#eda100'

plt.rcParams.update({
    'font.family': 'DejaVu Sans',
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.titleweight': 'bold',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'figure.facecolor': 'white',
})


def load_sweep():
    with open(SWEEP_PATH) as f:
        return json.load(f)


def _param_series(sweep, param, baseline_value):
    points = {baseline_value: sweep['baseline']}
    for key, result in sweep.items():
        if key.startswith(param + '='):
            value = float(key.split('=', 1)[1])
            points[value] = result
    xs = sorted(points)
    return xs, [points[x] for x in xs]


def _plot_param(sweep, param, baseline_value, xlabel, title, fname, log_x=False):
    xs, results = _param_series(sweep, param, baseline_value)
    tpr = [r['tpr'] for r in results]
    fpr = [r['fpr'] for r in results]
    f1 = [r['f1'] for r in results]

    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    ax.plot(xs, tpr, marker='o', color=BLUE, label='TPR (recall)')
    ax.plot(xs, f1, marker='s', color=AQUA, label='F1')
    ax.plot(xs, fpr, marker='^', color=YELLOW, label='FPR')
    ax.axvline(baseline_value, color='#999999', linestyle='--', linewidth=1)
    ax.text(baseline_value, ax.get_ylim()[1] * 0.02, ' deployed default',
            rotation=90, va='bottom', ha='right', fontsize=8, color='#666666')
    if log_x:
        ax.set_xscale('log')
    ax.set_xlabel(xlabel)
    ax.set_ylabel('Score')
    ax.set_ylim(-0.02, 1.05)
    ax.set_title(title)
    ax.legend(frameon=False, loc='center right')
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, fname)
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f'Saved {out}')


def fig_device_freshness_window(sweep):
    _plot_param(
        sweep, 'DEVICE_FRESHNESS_WINDOW_DAYS', 30.0,
        xlabel='Device posture freshness window (days)',
        title='Figure 3.14 — Device Posture Freshness Window Sensitivity',
        fname='Figure_3.14_Device_Posture_Freshness_Optimization.png',
    )


def fig_geo_mismatch_penalty(sweep):
    _plot_param(
        sweep, 'GEO_MISMATCH_PENALTY', 0.5,
        xlabel='GEO_MISMATCH_PENALTY (Cs multiplier on a GPS/WiFi/IP distance mismatch)',
        title='Figure 3.13 — Geographic Consistency Penalty Sensitivity',
        fname='Figure_3.13_Geographic_Consistency_Penalty.png',
    )


def fig_crit_tls_penalty(sweep):
    _plot_param(
        sweep, 'CRIT_TLS_PENALTY', 0.2,
        xlabel='CRIT_TLS_PENALTY (Es multiplier on a critical JA3 tag)',
        title='Figure 3.10 — Critical TLS Fingerprint Penalty Sensitivity',
        fname='Figure_3.10_Critical_TLS_Fingerprint_Penalty.png',
    )


def fig_device_tls_mismatch_penalty(sweep):
    _plot_param(
        sweep, 'DEVICE_TLS_MISMATCH_PENALTY', 0.4,
        xlabel='DEVICE_TLS_MISMATCH_PENALTY (Cs multiplier on a device/TLS platform mismatch)',
        title='Figure 3.11 — Device/TLS Platform Consistency Penalty Sensitivity',
        fname='Figure_3.11_Device_TLS_Platform_Mismatch_Penalty.png',
    )


def fig_missing_signal_penalty(sweep):
    """MISSING_SIGNAL_PENALTY shows no measurable effect in this dataset — a
    real, honest robustness finding (not a data gap): the simulator's
    _ensure_floors() guarantees near-complete signal sets, so the
    missing-signal completeness discount rarely fires. Plotted anyway so the
    null result is visible rather than silently dropped."""
    _plot_param(
        sweep, 'MISSING_SIGNAL_PENALTY', 0.3,
        xlabel='MISSING_SIGNAL_PENALTY (completeness discount per absent signal type)',
        title='Figure 3.12 — Missing-Signal Penalty Sensitivity (no measurable effect)',
        fname='Figure_3.12_Missing_Signal_Penalty.png',
    )


def fig_signal_weight_distribution():
    """Real distribution of each signal's normalized Wi across the live full
    run — not a sweep, but the direct empirical answer to "how much does
    quality-weighting actually move trust in practice?" (zta.validated_context.weights)."""
    dsn = os.environ['DB_DSN']
    conn = psycopg2.connect(dsn)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("select weights from zta.validated_context")
    rows = cur.fetchall()
    conn.close()

    keys = ['gps', 'wifi_bssid', 'ip_geo', 'device_posture', 'tls_fp']
    labels = ['GPS', 'WiFi\nBSSID', 'IP\nGeo', 'Device\nPosture', 'TLS\nFingerprint']
    data = {k: [] for k in keys}
    for r in rows:
        w = r['weights'] or {}
        for k in keys:
            if k in w:
                data[k].append(float(w[k]))

    fig, ax = plt.subplots(figsize=(6.8, 4.4))
    box_data = [data[k] for k in keys]
    bp = ax.boxplot(box_data, labels=labels, patch_artist=True, showfliers=False, widths=0.55)
    for patch in bp['boxes']:
        patch.set_facecolor(BLUE)
        patch.set_alpha(0.35)
    for median in bp['medians']:
        median.set_color(BLUE)
        median.set_linewidth(2)
    ax.axhline(0.2, color='#999999', linestyle='--', linewidth=1)
    ax.text(0.55, 0.205, 'equal share (1/5)', fontsize=8, color='#666666')
    ax.set_ylabel('Normalized weight Wi = Qi / ΣQi')
    ax.set_title(f'Figure 3.15 — Live Signal Weight Distribution (n={len(rows)} sessions)')
    fig.tight_layout()
    out = os.path.join(OUTPUT_DIR, 'Figure_3.15_Signal_Weights_Distribution.png')
    fig.savefig(out, dpi=150)
    plt.close(fig)
    print(f'Saved {out}')


if __name__ == '__main__':
    sweep = load_sweep()
    fig_device_freshness_window(sweep)
    fig_geo_mismatch_penalty(sweep)
    fig_crit_tls_penalty(sweep)
    fig_device_tls_mismatch_penalty(sweep)
    fig_missing_signal_penalty(sweep)
    fig_signal_weight_distribution()
