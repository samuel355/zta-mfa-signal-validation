#!/usr/bin/env python3
"""
Generate Figures 3.1-3.3 (architecture / process / feedback-loop diagrams)
programmatically, replacing the earlier static images. Content is drawn
directly from Chapter 3's implementation description (Sections 3.2.1-3.2.7),
not redrawn freehand — in particular the decision thresholds (0.24 / 0.75,
not the superseded 0.25) and the real enrichment lookups (no fabricated
"Device CVE Check").

Usage: python3 generate_architecture_figures.py
Writes: updated/figures/Figure_3.1_Proposed_Framework_Architecture.png
        updated/figures/Figure_3.2_Context_Signal_Validation_Process.png
        updated/figures/Figure_3.3_SIEM_STRIDE_Feedback_Loop.png
"""
import os
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.path import Path as MplPath

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'updated', 'figures')

# Palette consistent with generate_chapter4_figures.py's validated categorical set.
BOX_FILL = '#dbeafe'      # light blue (box interior)
BOX_EDGE = '#2a78d6'      # blue (box border) — same hue as "proposed" elsewhere
GROUP_FILL = '#2a78d6'    # blue (group/container background)
GROUP_TEXT = 'white'
DECISION_FILL = '#eda100'  # amber (decision diamonds)
ARROW_COLOR = '#333333'
TEXT_COLOR = '#111111'


def _box(ax, x, y, w, h, text, fontsize=10.5, fill=BOX_FILL, edge=BOX_EDGE,
          text_color=TEXT_COLOR, weight='normal', zorder=3):
    b = FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.02,rounding_size=0.06',
                        linewidth=1.3, edgecolor=edge, facecolor=fill, zorder=zorder)
    ax.add_patch(b)
    ax.text(x + w / 2, y + h / 2, text, ha='center', va='center',
             fontsize=fontsize, color=text_color, weight=weight, zorder=zorder + 1,
             linespacing=1.35)
    return (x, y, w, h)


def _diamond(ax, cx, cy, w, h, text, fontsize=9.5):
    pts = [(cx, cy + h / 2), (cx + w / 2, cy), (cx, cy - h / 2), (cx - w / 2, cy), (cx, cy + h / 2)]
    path = MplPath(pts)
    from matplotlib.patches import PathPatch
    p = PathPatch(path, facecolor=DECISION_FILL, edgecolor='#8a5c00', linewidth=1.2, zorder=3)
    ax.add_patch(p)
    ax.text(cx, cy, text, ha='center', va='center', fontsize=fontsize, weight='bold', zorder=4)


def _arrow(ax, xy_from, xy_to, style='-|>', color=ARROW_COLOR, lw=1.4, connectionstyle='arc3,rad=0.0', ls='-'):
    a = FancyArrowPatch(xy_from, xy_to, arrowstyle=style, color=color, linewidth=lw,
                         connectionstyle=connectionstyle, linestyle=ls, zorder=2,
                         mutation_scale=14)
    ax.add_patch(a)


def _label(ax, x, y, text, fontsize=9, color='#555555', style='normal', weight='normal', ha='center'):
    ax.text(x, y, text, ha=ha, va='center', fontsize=fontsize, color=color, style=style, weight=weight)


def _new_ax(figsize):
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, 10)
    ax.axis('off')
    return fig, ax


# ---------------------------------------------------------------------------
# Figure 3.1 — Proposed Framework Architecture
# ---------------------------------------------------------------------------
def fig_3_1():
    fig, ax = _new_ax((9, 10))
    ax.set_ylim(0, 12.5)
    ax.set_title('Figure 3.1: Proposed Framework Architecture', fontsize=13, fontweight='bold', pad=14)

    _box(ax, 0.4, 10.6, 3.0, 1.3,
         'Endpoint\n(Remote User /\nSession Simulator)', fontsize=9.5)
    _box(ax, 4.2, 10.6, 5.4, 1.3,
         'Telemetry: GPS, IP, Wi-Fi BSSID,\nDevice Posture, TLS/JA3 Fingerprint,\nNetwork-Flow Statistics (3.2.1)', fontsize=9)
    _arrow(ax, (3.4, 11.25), (4.2, 11.25))

    # Validation layer group
    _box(ax, 0.4, 7.7, 9.2, 2.4, '', fill=GROUP_FILL, edge=GROUP_FILL, zorder=1)
    ax.text(0.6, 9.85, 'Contextual Signal Validation Layer (services/validation, 3.2.2)',
            fontsize=10.5, weight='bold', color=GROUP_TEXT, ha='left')
    _box(ax, 0.7, 8.5, 2.7, 1.0, 'Enrichment:\nGeoLite2 / WiGLE /\nJA3-tag / Device DB', fontsize=8.3, zorder=2)
    _box(ax, 3.6, 8.5, 2.7, 1.0, 'Cross-source\nConsistency:\nHaversine, OS/TLS', fontsize=8.3, zorder=2)
    _box(ax, 6.5, 8.5, 2.9, 1.0, 'Qs = Fs x Cs x Es\nper signal ->\nweights Wi (3.2.2)', fontsize=8.3, zorder=2)
    _arrow(ax, (5.55, 9.5), (5.55, 9.7))
    _arrow(ax, (3.4, 9.0), (3.6, 9.0))
    _arrow(ax, (6.3, 9.0), (6.5, 9.0))
    _arrow(ax, (2.05, 10.6), (2.05, 9.5))

    _arrow(ax, (5.05, 7.7), (5.05, 7.2))

    # Network-flow classifiers
    _box(ax, 0.4, 5.9, 9.2, 1.2,
         '4 Trained Random Forest Classifiers (3.2.6): Denial of Service, Elevation of\n'
         'Privilege, Credential Attack, Infiltration -> STRIDE reason codes', fontsize=9)
    _arrow(ax, (5.05, 5.9), (5.05, 5.4))

    # Trust / risk engine
    _box(ax, 0.4, 4.0, 9.2, 1.4,
         'Risk-Scoring Engine (services/trust, 3.2.3)\n'
         'Base + Device + Location + TLS + STRIDE-reason + SIEM risk -> R in [0,1]', fontsize=9.3)
    _arrow(ax, (5.05, 4.0), (5.05, 3.5))

    # Decision thresholds — corrected
    _box(ax, 0.4, 2.5, 9.2, 1.0,
         'Policy: ALLOW if R < 0.24  |  STEP-UP MFA if 0.24 <= R < 0.75  |  DENY if R >= 0.75  (3.5.2)',
         fontsize=9.3, fill='#fff3d6', edge='#b8860b')
    _arrow(ax, (5.05, 2.5), (5.05, 2.0))

    _box(ax, 0.4, 0.9, 3.0, 1.1, 'Authentication\nGateway (MFA\nOrchestrator, 3.2.4)', fontsize=9)
    _box(ax, 3.9, 0.9, 2.6, 1.1, 'Protected\nResources', fontsize=9.5)
    _box(ax, 6.9, 0.9, 2.7, 1.1, 'SIEM & STRIDE\nCorrelation\n(Figure 3.3)', fontsize=8.8)
    _arrow(ax, (3.4, 1.45), (3.9, 1.45))
    _arrow(ax, (6.5, 1.45), (6.9, 1.45))
    _arrow(ax, (8.25, 2.5), (8.25, 2.0), connectionstyle='arc3,rad=-0.35', color='#888888', ls='--')
    _label(ax, 9.0, 2.25, 'feedback', fontsize=7.5, color='#888888')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_3.1_Proposed_Framework_Architecture.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 3.2 — Context Signal Validation Process
# ---------------------------------------------------------------------------
def fig_3_2():
    fig, ax = _new_ax((9.5, 11))
    ax.set_ylim(0, 13.5)
    ax.set_title('Figure 3.2: Context Signal Validation Process', fontsize=13, fontweight='bold', pad=14)

    _box(ax, 3.3, 12.3, 3.4, 0.8, 'Start Authentication Request', fontsize=9.5)
    _arrow(ax, (5.0, 12.3), (5.0, 11.9))

    _box(ax, 3.3, 11.1, 3.4, 0.8, 'Collect Raw Context Signals', fontsize=9.5)
    _arrow(ax, (5.0, 11.1), (5.0, 10.7))

    # Enrichment lookups (real ones only — no fabricated CVE check)
    _box(ax, 0.4, 9.5, 9.2, 1.2, '', fill=GROUP_FILL, edge=GROUP_FILL, zorder=1)
    ax.text(0.6, 10.5, 'Enrichment Lookups (3.2.2)', fontsize=9.5, weight='bold', color=GROUP_TEXT, ha='left')
    _box(ax, 0.65, 9.65, 2.1, 0.65, 'GeoLite2\n(IP geolocation)', fontsize=7.6, zorder=2)
    _box(ax, 2.9, 9.65, 2.05, 0.65, 'WiGLE\n(Wi-Fi BSSID)', fontsize=7.6, zorder=2)
    _box(ax, 5.1, 9.65, 2.05, 0.65, 'JA3 tag lookup\n(TLS fingerprint)', fontsize=7.6, zorder=2)
    _box(ax, 7.3, 9.65, 2.1, 0.65, 'Device posture DB\n(patched / EDR)', fontsize=7.6, zorder=2)
    _arrow(ax, (5.0, 10.7), (5.0, 10.7))
    _arrow(ax, (5.0, 11.1), (5.0, 10.75))

    _arrow(ax, (5.0, 9.5), (5.0, 9.0))

    # Consistency + freshness
    _box(ax, 0.4, 7.7, 4.4, 1.1,
         'Consistency (Cs): Haversine cross-check\n(GPS/Wi-Fi/IP); device OS vs. TLS platform', fontsize=8.3)
    _box(ax, 5.2, 7.7, 4.4, 1.1,
         'Freshness (Fs): device-posture check-in\nage / window; Fs=1.0 for live-captured signals', fontsize=8.3)
    _arrow(ax, (2.6, 9.0), (2.6, 8.8))
    _arrow(ax, (7.4, 9.0), (7.4, 8.8))
    _arrow(ax, (2.6, 7.7), (4.6, 7.25))
    _arrow(ax, (7.4, 7.7), (5.4, 7.25))

    _box(ax, 3.0, 6.6, 4.0, 0.75, 'Qs = Fs x Cs x Es -> Wi = Qi / sum(Qi)', fontsize=9)
    _arrow(ax, (5.0, 6.6), (5.0, 6.15))

    # Classifiers
    _box(ax, 0.4, 5.05, 9.2, 1.1,
         'Network-flow classifiers (3.2.6): DoS, Elevation of Privilege,\nCredential Attack, Infiltration -> STRIDE reason codes', fontsize=8.8)
    _arrow(ax, (5.0, 5.05), (5.0, 4.55))

    _box(ax, 2.6, 3.5, 4.8, 1.0,
         'Aggregate Risk Score R\n(base + device + location + TLS + STRIDE + SIEM, 3.2.3)', fontsize=8.6)
    _arrow(ax, (5.0, 3.5), (5.0, 2.95))

    _diamond(ax, 5.0, 2.35, 3.6, 1.15, 'R vs.\nALLOW_T / DENY_T?', fontsize=8.3)

    _arrow(ax, (3.2, 2.35), (1.55, 2.35))
    _arrow(ax, (6.8, 2.35), (8.45, 2.35))
    _arrow(ax, (5.0, 1.75), (5.0, 1.1))

    _box(ax, 0.15, 1.85, 2.8, 0.9, 'R < 0.24\nALLOW', fontsize=8.6, fill='#dff5e3', edge='#1baf7a')
    _box(ax, 3.6, 0.6, 2.8, 0.9, 'STEP-UP MFA\n0.24 <= R < 0.75', fontsize=8.4, fill='#fff3d6', edge='#b8860b')
    _box(ax, 7.05, 1.85, 2.8, 0.9, 'R >= 0.75\nDENY', fontsize=8.6, fill='#fde2e1', edge='#e34948')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_3.2_Context_Signal_Validation_Process.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


# ---------------------------------------------------------------------------
# Figure 3.3 — SIEM/STRIDE Feedback Loop
# ---------------------------------------------------------------------------
def fig_3_3():
    fig, ax = _new_ax((11.5, 6.2))
    ax.set_xlim(-2.1, 13)
    ax.set_ylim(0, 6.2)
    ax.set_title('Figure 3.3: SIEM / STRIDE Feedback Loop', fontsize=13, fontweight='bold', pad=12)

    _box(ax, 0.3, 3.9, 2.6, 1.0, 'Gateway\nDecision\n(step-up / deny)', fontsize=8.6)
    _box(ax, 3.5, 3.9, 3.0, 1.0,
         'STRIDE priority mapping\n(fixed order, 3.2.5):\nRepudiation > DoS > Spoofing\n> EoP > Info.Disclosure > Tampering', fontsize=7.4)
    _box(ax, 7.1, 3.9, 2.6, 1.0, 'SIEM Alert Log\n(zta.siem_alerts)', fontsize=8.6)
    _box(ax, 10.2, 3.9, 2.5, 1.0, 'Aggregate Query\n(session_id,\n15-min window)', fontsize=8.3)

    _arrow(ax, (2.9, 4.4), (3.5, 4.4))
    _arrow(ax, (6.5, 4.4), (7.1, 4.4))
    _arrow(ax, (9.7, 4.4), (10.2, 4.4))

    _box(ax, 5.2, 1.6, 3.2, 1.0, 'SIEM Risk Term\n(3.2.3): high/medium\nalert bumps, scaled\nby confidence', fontsize=7.8)
    _arrow(ax, (11.45, 3.9), (11.45, 2.6), connectionstyle='arc3,rad=0.0')
    _arrow(ax, (11.45, 2.6), (8.4, 2.1), connectionstyle='arc3,rad=-0.15')

    _box(ax, 0.3, 1.6, 3.6, 1.0, 'Risk-Scoring Engine\n(next session sharing\nthe same session_id)', fontsize=8.0)
    _arrow(ax, (5.2, 2.1), (3.9, 2.1))

    # Single loop-back arrow (one continuous arc, one arrowhead), routed
    # through the open left margin so it never crosses either box; the label
    # sits further left still, clear of the curve itself.
    _arrow(ax, (0.3, 2.1), (0.3, 4.4), connectionstyle='arc3,rad=1.15', ls='--', color='#888888')
    _label(ax, -1.75, 3.15, 'feeds into the\nnext session\nsharing this\nsession_id', fontsize=7, color='#888888', ha='center')

    plt.tight_layout()
    out = f'{OUTPUT_DIR}/Figure_3.3_SIEM_STRIDE_Feedback_Loop.png'
    plt.savefig(out, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close()
    print(f'Saved {out}')


if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    fig_3_1()
    fig_3_2()
    fig_3_3()
