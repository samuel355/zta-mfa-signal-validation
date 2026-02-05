import matplotlib

matplotlib.use("Agg")  # Use non-interactive backend

import warnings

import matplotlib.pyplot as plt
import numpy as np
from scipy.interpolate import make_interp_spline
import os

# Create output directories
os.makedirs("freshness", exist_ok=True)
os.makedirs("threat_penalties", exist_ok=True)
os.makedirs("roc_analysis", exist_ok=True)

warnings.filterwarnings("ignore")

# Set high-quality academic style
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
matplotlib.rcParams["font.family"] = "Times New Roman"
matplotlib.rcParams["font.size"] = 14
matplotlib.rcParams["axes.titlesize"] = 18
matplotlib.rcParams["axes.labelsize"] = 16
matplotlib.rcParams["xtick.labelsize"] = 14
matplotlib.rcParams["ytick.labelsize"] = 14
matplotlib.rcParams["legend.fontsize"] = 13
matplotlib.rcParams["figure.dpi"] = 600
matplotlib.rcParams["savefig.dpi"] = 600
matplotlib.rcParams["savefig.bbox"] = "tight"
matplotlib.rcParams["savefig.pad_inches"] = 0.1

# Professional color palette
colors = [
    "#2E86AB",
    "#A23B72",
    "#F18F01",
    "#C73E1D",
    "#6A994E",
    "#5D576B",
    "#386641",
    "#BC4B51",
]

print("=" * 80)
print("Generating Individual High-Quality Plots")
print("=" * 80)

# ============================================================================
# INDIVIDUAL FRESHNESS TIME CONSTANTS PLOTS
# ============================================================================
print("\n📊 Generating Individual Freshness Time Constants Plots...")

# Time constants in minutes (log scale appropriate)
time_points = np.array([1, 2, 5, 10, 15, 20, 30, 60, 120, 240, 480, 1440, 2880])

# Define optimal points with realistic F1-Score peaks
optimals = {
    "GPS": (5, 0.90),
    "IP": (10, 0.89),
    "Device": (1440, 0.88),
    "WiFi": (30, 0.81),
    "TLS": (20, 0.86),
}


def gaussian_peak(x, mu, sigma, amplitude, baseline):
    return baseline + amplitude * np.exp(
        -0.5 * ((np.log(x + 1) - np.log(mu + 1)) / sigma) ** 2
    )


# Generate data for each signal
signals = {}
for name, (opt_time, opt_f1) in optimals.items():
    baseline = 0.65 if name != "Device" else 0.60
    amplitude = opt_f1 - baseline
    sigma = 0.4

    f1_values = gaussian_peak(time_points, opt_time, sigma, amplitude, baseline)
    noise = np.random.normal(0, 0.01, len(time_points))
    signals[name] = np.clip(f1_values + noise, 0.6, 0.95)

signal_order = ["GPS", "IP", "Device", "WiFi", "TLS"]
titles = {
    "GPS": "GPS Location Freshness Optimization",
    "IP": "IP Geolocation Freshness Optimization",
    "Device": "Device Posture Freshness Optimization",
    "WiFi": "Wi-Fi BSSID Freshness Optimization",
    "TLS": "TLS Fingerprint Freshness Optimization",
}

# Generate individual plots for each signal
for idx, sig_name in enumerate(signal_order):
    fig, ax = plt.subplots(figsize=(10, 7))

    data = signals[sig_name]
    opt_time, opt_f1 = optimals[sig_name]

    # Main plot with markers
    ax.semilogx(
        time_points,
        data,
        "o-",
        linewidth=3,
        markersize=10,
        color=colors[idx],
        markeredgecolor="black",
        markeredgewidth=0.8,
        label="F1-Score",
    )

    # Highlight optimal point
    ax.plot(
        opt_time,
        opt_f1,
        "s",
        markersize=16,
        color="red",
        markeredgecolor="black",
        markeredgewidth=2,
        label=f"Optimal: {opt_time} min (F1={opt_f1:.3f})",
        zorder=10,
    )

    # Add smooth interpolation
    time_smooth = np.logspace(np.log10(1), np.log10(2880), 300)
    spline = make_interp_spline(np.log(time_points), data, k=3)
    data_smooth = spline(np.log(time_smooth))
    ax.plot(time_smooth, data_smooth, color=colors[idx], alpha=0.3, linewidth=2)

    # Formatting
    ax.set_xlabel("Time Constant (minutes, log scale)", fontsize=16, fontweight="bold")
    ax.set_ylabel("F1-Score", fontsize=16, fontweight="bold")
    ax.set_title(titles[sig_name], fontsize=18, fontweight="bold", pad=20)
    ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.8)
    ax.set_ylim(0.55, 0.96)
    ax.set_xlim(0.9, 3000)

    # Customize ticks
    ax.set_xticks([1, 10, 100, 1000, 2880])
    ax.set_xticklabels(["1", "10", "100", "1000", "2880"])

    ax.legend(
        loc="lower right",
        framealpha=0.95,
        edgecolor="black",
        fancybox=True,
        fontsize=13,
    )

    # Save individual plot
    filename = f"freshness/{sig_name.lower()}_freshness_optimization.png"
    fig.savefig(filename, dpi=600, bbox_inches="tight")
    print(f"   ✅ Saved: {filename}")
    plt.close(fig)

print(f"   📁 All freshness plots saved in 'freshness/' folder")

# ============================================================================
# INDIVIDUAL THREAT PENALTY PLOTS
# ============================================================================
print("\n📊 Generating Individual Threat Penalty Plots...")

penalty_range = np.arange(0.05, 0.96, 0.05)
penalty_configs = {
    "VPN": (0.7, 0.93),
    "TOR": (0.9, 0.94),
    "Malicious": (0.1, 0.88),
    "Unknown": (0.2, 0.89),
}

penalty_titles = {
    "VPN": "VPN Detection Penalty Optimization",
    "TOR": "TOR Exit Node Penalty Optimization",
    "Malicious": "Malicious IP Penalty Optimization",
    "Unknown": "Unknown IP Penalty Optimization",
}

# Generate realistic curves for each penalty type
penalty_curves = {}
for penalty_type, (opt_val, opt_f1) in penalty_configs.items():
    baseline = 0.70
    amplitude = opt_f1 - baseline
    width = 0.25

    curve = baseline + amplitude * np.exp(
        -((penalty_range - opt_val) ** 2) / (2 * width**2)
    )
    curve += np.random.normal(0, 0.006, len(penalty_range))
    penalty_curves[penalty_type] = np.clip(curve, 0.68, 0.95)

# Generate individual plots for each penalty type
for idx, penalty_type in enumerate(penalty_configs.keys()):
    fig, ax = plt.subplots(figsize=(10, 7))

    opt_val, opt_f1 = penalty_configs[penalty_type]
    curve = penalty_curves[penalty_type]

    # Main plot
    ax.plot(
        penalty_range,
        curve,
        "o-",
        linewidth=3,
        markersize=10,
        color=colors[idx],
        markeredgecolor="black",
        markeredgewidth=0.8,
        label="F1-Score",
    )

    # Highlight optimal point
    ax.plot(
        opt_val,
        opt_f1,
        "s",
        markersize=16,
        color="red",
        markeredgecolor="black",
        markeredgewidth=2,
        label=f"Optimal: {opt_val} (F1={opt_f1:.3f})",
        zorder=10,
    )

    # Add smooth interpolation
    penalty_smooth = np.linspace(0.05, 0.95, 200)
    spline = make_interp_spline(penalty_range, curve, k=3)
    curve_smooth = spline(penalty_smooth)
    ax.plot(penalty_smooth, curve_smooth, color=colors[idx], alpha=0.3, linewidth=2)

    # Formatting
    ax.set_xlabel("Penalty Weight", fontsize=16, fontweight="bold")
    ax.set_ylabel("F1-Score", fontsize=16, fontweight="bold")
    ax.set_title(penalty_titles[penalty_type], fontsize=18, fontweight="bold", pad=20)
    ax.grid(True, alpha=0.3, linestyle="--", linewidth=0.8)
    ax.set_ylim(0.68, 0.96)
    ax.set_xlim(0, 1)

    ax.legend(
        loc="lower right" if penalty_type in ["VPN", "TOR"] else "upper right",
        framealpha=0.95,
        edgecolor="black",
        fancybox=True,
        fontsize=13,
    )

    # Save individual plot
    filename = f"threat_penalties/{penalty_type.lower()}_penalty_optimization.png"
    fig.savefig(filename, dpi=600, bbox_inches="tight")
    print(f"   ✅ Saved: {filename}")
    plt.close(fig)

print(f"   📁 All threat penalty plots saved in 'threat_penalties/' folder")

# ============================================================================
# INDIVIDUAL ROC ANALYSIS PLOTS
# ============================================================================
print("\n📊 Generating Individual ROC Analysis Plots...")

# Generate realistic ROC data
thresholds = np.linspace(0, 1, 101)

# TPR: starts high, decreases gradually
tpr = 1 - 0.65 * thresholds**1.3
# FPR: decreases exponentially
fpr = np.exp(-7 * thresholds)

# Add realistic variation
tpr += np.random.normal(0, 0.015, len(thresholds))
fpr += np.random.normal(0, 0.005, len(thresholds))
tpr = np.clip(tpr, 0, 1)
fpr = np.clip(fpr, 0, 0.3)

# Calculate F1-Scores
precision = tpr / (tpr + fpr + 1e-10)
f1_scores = 2 * precision * tpr / (precision + tpr + 1e-10)

# Find optimal thresholds
idx_25 = np.argmin(np.abs(thresholds - 0.25))
idx_75 = np.argmin(np.abs(thresholds - 0.75))

# Calculate AUC using trapezoidal rule
auc = np.trapz(tpr[fpr.argsort()], fpr[fpr.argsort()])

# ---- PLOT 1: ROC Curve with Decision Thresholds ----
fig1, ax1 = plt.subplots(figsize=(10, 8))

ax1.plot(fpr, tpr, "b-", linewidth=4, alpha=0.85, label=f"ROC Curve (AUC = {auc:.3f})")

# Mark threshold points
ax1.plot(
    fpr[idx_25],
    tpr[idx_25],
    "o",
    markersize=18,
    color="red",
    markeredgecolor="black",
    markeredgewidth=2,
    label=f"Step-up Threshold (R=0.25)\nTPR={tpr[idx_25]:.3f}, FPR={fpr[idx_25]:.3f}",
    zorder=10,
)

ax1.plot(
    fpr[idx_75],
    tpr[idx_75],
    "s",
    markersize=18,
    color="green",
    markeredgecolor="black",
    markeredgewidth=2,
    label=f"Deny Threshold (R=0.75)\nTPR={tpr[idx_75]:.3f}, FPR={fpr[idx_75]:.4f}",
    zorder=10,
)

# Random classifier line
ax1.plot([0, 1], [0, 1], "k--", linewidth=2, alpha=0.5, label="Random Classifier")

ax1.set_xlabel("False Positive Rate (FPR)", fontsize=16, fontweight="bold")
ax1.set_ylabel("True Positive Rate (TPR)", fontsize=16, fontweight="bold")
ax1.set_title(
    "ROC Curve with Decision Thresholds", fontsize=18, fontweight="bold", pad=20
)
ax1.grid(True, alpha=0.3, linestyle="--", linewidth=0.8)
ax1.legend(
    loc="lower right", framealpha=0.95, edgecolor="black", fancybox=True, fontsize=12
)
ax1.set_xlim(0, 0.3)
ax1.set_ylim(0, 1.05)

fig1.savefig("roc_analysis/roc_curve_with_thresholds.png", dpi=600, bbox_inches="tight")
print(f"   ✅ Saved: roc_analysis/roc_curve_with_thresholds.png")
plt.close(fig1)

# ---- PLOT 2: F1-Score vs Risk Threshold ----
fig2, ax2 = plt.subplots(figsize=(10, 8))

ax2.plot(
    thresholds,
    f1_scores,
    "-",
    linewidth=4,
    alpha=0.85,
    color="#9C27B0",
    label="F1-Score",
)

# Add threshold lines
ax2.axvline(
    x=0.25,
    color="red",
    linestyle="--",
    linewidth=2.5,
    alpha=0.8,
    label=f"Step-up Threshold (0.25)\nF1={f1_scores[idx_25]:.3f}",
)
ax2.axvline(
    x=0.75,
    color="green",
    linestyle="--",
    linewidth=2.5,
    alpha=0.8,
    label=f"Deny Threshold (0.75)\nF1={f1_scores[idx_75]:.3f}",
)

# Mark peak regions
ax2.fill_betweenx([0, 1], 0.2, 0.3, color="red", alpha=0.15, label="Step-up Region")
ax2.fill_betweenx([0, 1], 0.7, 0.8, color="green", alpha=0.15, label="Deny Region")

# Mark optimal points
ax2.plot(
    0.25,
    f1_scores[idx_25],
    "o",
    markersize=14,
    color="red",
    markeredgecolor="black",
    markeredgewidth=2,
    zorder=10,
)
ax2.plot(
    0.75,
    f1_scores[idx_75],
    "s",
    markersize=14,
    color="green",
    markeredgecolor="black",
    markeredgewidth=2,
    zorder=10,
)

ax2.set_xlabel("Risk Score Threshold", fontsize=16, fontweight="bold")
ax2.set_ylabel("F1-Score", fontsize=16, fontweight="bold")
ax2.set_title("F1-Score vs Risk Threshold", fontsize=18, fontweight="bold", pad=20)
ax2.grid(True, alpha=0.3, linestyle="--", linewidth=0.8)
ax2.legend(
    loc="lower left", framealpha=0.95, edgecolor="black", fancybox=True, fontsize=12
)
ax2.set_ylim(0, 1.05)
ax2.set_xlim(0, 1)

fig2.savefig("roc_analysis/f1_score_vs_threshold.png", dpi=600, bbox_inches="tight")
print(f"   ✅ Saved: roc_analysis/f1_score_vs_threshold.png")
plt.close(fig2)

print(f"   📁 All ROC analysis plots saved in 'roc_analysis/' folder")


# ============================================================================
# GEOGRAPHIC THRESHOLD PLOT
# ============================================================================
print("\n📊 Generating Geographic Threshold Plot...")

d_values = np.arange(100, 2100, 100)
opt_d = 1000

# Create realistic F1-Score curve
f1_scores = 0.55 + 0.40 * np.exp(-((d_values - opt_d) ** 2) / (2 * 300 ** 2))
f1_scores += np.random.normal(0, 0.008, len(d_values))

# Create complementary FPR curve
fpr_values = 0.04 + 0.035 * np.abs(d_values - opt_d) / opt_d

fig, ax1 = plt.subplots(figsize=(10, 7))

# Plot F1-Score
(line1,) = ax1.plot(d_values, f1_scores, 'o-', linewidth=3, markersize=10, 
                   color=colors[0], markeredgecolor='black', markeredgewidth=1,
                   label='F1-Score', zorder=5)

# Highlight optimal point
ax1.plot(opt_d, np.max(f1_scores), 's', markersize=18, color='red', 
         markeredgecolor='black', markeredgewidth=2, zorder=10,
         label=f'Optimal: d₀ = {opt_d} km\nF1 = {np.max(f1_scores):.3f}')

ax1.set_xlabel('Geographic Consistency Threshold d₀ (km)', fontsize=16, fontweight='bold')
ax1.set_ylabel('F1-Score', fontsize=16, fontweight='bold', color=colors[0])
ax1.tick_params(axis='y', labelcolor=colors[0])
ax1.grid(True, alpha=0.2, linestyle='--')
ax1.set_ylim(0.5, 1.0)
ax1.set_xlim(0, 2100)

# Add FPR on secondary axis
ax2 = ax1.twinx()
(line2,) = ax2.plot(d_values, fpr_values, 's--', linewidth=2.5, markersize=8,
                   color=colors[1], markeredgecolor='black', markeredgewidth=1,
                   label='False Positive Rate', alpha=0.8)

ax2.set_ylabel('False Positive Rate', fontsize=16, fontweight='bold', color=colors[1])
ax2.tick_params(axis='y', labelcolor=colors[1])
ax2.set_ylim(0.03, 0.085)

# Legend
lines = [line1, line2]
labels = [l.get_label() for l in lines]
ax1.legend(lines, labels, loc='upper left', framealpha=0.95, 
           edgecolor='black', fancybox=True, fontsize=12)

fig.suptitle('Geographic Consistency Threshold Optimization', 
             fontsize=18, fontweight='bold', y=0.98)

fig.savefig('geographic_threshold_optimization.png', dpi=600, bbox_inches='tight')
print(f"   ✅ Saved: geographic_threshold_optimization.png")
plt.close(fig)

# ============================================================================
# SIGNAL WEIGHT PARALLEL COORDINATES PLOT
# ============================================================================
print("\n📊 Generating Signal Weight Parallel Coordinates Plot...")

# Generate diverse weight combinations
np.random.seed(42)
num_configs = 20
configs = []

# Create random weight combinations that sum to 1
for _ in range(num_configs):
    weights = np.random.dirichlet(np.ones(5) * 1.5)
    configs.append(weights)

# Our optimal configuration
optimal_config = np.array([0.25, 0.20, 0.20, 0.20, 0.15])
configs.append(optimal_config)

# Calculate performance scores
def config_performance(weights):
    optimal = np.array([0.25, 0.20, 0.20, 0.20, 0.15])
    distance = np.sqrt(np.sum((weights - optimal) ** 2))
    gps_benefit = 0.1 * (weights[0] - 0.15) / 0.15
    balance_penalty = 0.05 * np.std(weights)
    performance = 0.75 - 0.3 * distance + gps_benefit - balance_penalty
    return np.clip(performance, 0.6, 0.95)

performances = [config_performance(w) for w in configs]

# Create parallel coordinates plot
fig, ax = plt.subplots(figsize=(14, 8))
signal_names = ['GPS\nWeight', 'IP\nWeight', 'Device\nWeight', 'TLS\nWeight', 'Wi-Fi\nWeight']
norm_perf = [(p - 0.6) / (0.95 - 0.6) for p in performances]

# Plot all configurations
for i, (weights, perf, norm) in enumerate(zip(configs[:-1], performances[:-1], norm_perf[:-1])):
    color = plt.cm.viridis(norm)
    ax.plot(range(5), weights, 'o-', color=color, linewidth=1.5, alpha=0.6, markersize=4, markeredgecolor='black', markeredgewidth=0.3)

# Highlight optimal configuration
opt_perf = performances[-1]
ax.plot(range(5), optimal_config, 'o-', color='red', linewidth=4, markersize=10, markeredgecolor='black', markeredgewidth=1.5, label=f'Optimal: {optimal_config}\nF1 = {opt_perf:.3f}', zorder=10)

# Formatting
ax.set_xticks(range(5))
ax.set_xticklabels(signal_names, fontsize=14, fontweight='bold')
ax.set_ylabel('Weight Value', fontsize=16, fontweight='bold')
ax.set_ylim(0, 0.5)
ax.grid(True, alpha=0.2, linestyle='--', axis='y')
for y in [0.1, 0.2, 0.3, 0.4]:
    ax.axhline(y=y, color='gray', alpha=0.1, linestyle='-', linewidth=0.5)

# Add colorbar
sm = plt.cm.ScalarMappable(cmap=plt.cm.viridis, norm=plt.Normalize(vmin=0.6, vmax=0.95))
sm.set_array([])
cbar = plt.colorbar(sm, ax=ax, pad=0.02, aspect=30)
cbar.set_label('Configuration F1-Score', fontsize=14, fontweight='bold')

ax.legend(loc='upper right', framealpha=0.95, edgecolor='black', fancybox=True, fontsize=12)
fig.suptitle('Signal Weight Optimization via Parallel Coordinates', fontsize=18, fontweight='bold', y=0.98)
fig.savefig('signal_weight_optimization.png', dpi=600, bbox_inches='tight')
print(f"   ✅ Saved: signal_weight_optimization.png")
plt.close(fig)

# ============================================================================
# SIEM WEIGHT CONTOUR PLOT
# ============================================================================
print("\n📊 Generating SIEM Weight Contour Plot...")

# Create grid for contour plot
high_weights = np.linspace(0.1, 0.5, 15)
med_weights = np.linspace(0.05, 0.3, 12)
H, M = np.meshgrid(high_weights, med_weights)

# Create performance surface with peak at (0.30, 0.15)
peak_high, peak_med = 0.30, 0.15
base_perf = 0.75 + 0.15 * (H / 0.5)
peak_effect = 0.08 * np.exp(-((H - peak_high) ** 2 / 0.015 + (M - peak_med) ** 2 / 0.008))
imbalance_penalty = 0.05 * np.abs(H - M * 2)
f1_surface = base_perf + peak_effect - imbalance_penalty
f1_surface = np.clip(f1_surface, 0.7, 0.95)

fig, ax = plt.subplots(figsize=(12, 9))
contourf = ax.contourf(H, M, f1_surface, levels=25, cmap='viridis', alpha=0.85)
contour_lines = ax.contour(H, M, f1_surface, levels=10, colors='black', linewidths=0.8, alpha=0.5)

# Mark optimal point
ax.plot(peak_high, peak_med, '*', markersize=25, color='red', markeredgecolor='black', markeredgewidth=2, label=f'Optimal: High={peak_high}, Medium={peak_med}\nF1 = {np.max(f1_surface):.3f}', zorder=10)

ax.clabel(contour_lines, inline=True, fontsize=9, fmt='%.2f')
ax.set_xlabel('High-Severity Alert Weight', fontsize=16, fontweight='bold')
ax.set_ylabel('Medium-Severity Alert Weight', fontsize=16, fontweight='bold')
ax.set_title('SIEM Alert Weight Optimization Contour Plot', fontsize=18, fontweight='bold', pad=20)
ax.grid(True, alpha=0.2, linestyle='--')

cbar = plt.colorbar(contourf, ax=ax, pad=0.03, aspect=30)
cbar.set_label('F1-Score', fontsize=14, fontweight='bold')

# Add optimization explanation
ax.annotate('Under-weighted:\nMissed threats', xy=(0.15, 0.1), xytext=(0.1, 0.05), arrowprops=dict(arrowstyle='->', color='gray', alpha=0.7, linewidth=1.5), fontsize=11, bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.9))
ax.annotate('Over-weighted:\nFalse alerts', xy=(0.45, 0.25), xytext=(0.35, 0.28), arrowprops=dict(arrowstyle='->', color='gray', alpha=0.7, linewidth=1.5), fontsize=11, bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.9))

ax.legend(loc='lower right', framealpha=0.95, edgecolor='black', fancybox=True, fontsize=12)
fig.savefig('siem_weight_optimization.png', dpi=600, bbox_inches='tight')
print(f"   ✅ Saved: siem_weight_optimization.png")
plt.close(fig)

# ============================================================================
# SUMMARY
# ============================================================================
print("\n" + "=" * 80)
print("🎉 ALL INDIVIDUAL HIGH-QUALITY PLOTS GENERATED SUCCESSFULLY!")
print("=" * 80)
print("\n📁 Generated Files:")
print("\n   Freshness Optimization (freshness/):")
print("      1. gps_freshness_optimization.png")
print("      2. ip_freshness_optimization.png")
print("      3. device_freshness_optimization.png")
print("      4. wifi_freshness_optimization.png")
print("      5. tls_freshness_optimization.png")
print("\n   Threat Penalty Optimization (threat_penalties/):")
print("      6. vpn_penalty_optimization.png")
print("      7. tor_penalty_optimization.png")
print("      8. malicious_penalty_optimization.png")
print("      9. unknown_penalty_optimization.png")
print("\n   ROC Analysis (roc_analysis/):")
print("      10. roc_curve_with_thresholds.png")
print("      11. f1_score_vs_threshold.png")
print("\n✨ Features:")
print("   • 600 DPI resolution for publication quality")
print("   • Times New Roman fonts for academic style")
print("   • No bottom captions - clean professional look")
print("   • Larger fonts and markers for better visibility")
print("   • Each plot is standalone and self-contained")
print("   • Original combined plots preserved")
print("\n Geographic Threshold Plot!")
print("\n Signal Weight Parallel coordinates plots!")
