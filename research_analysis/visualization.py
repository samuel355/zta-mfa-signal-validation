"""
Visualization Module for Zero Trust MFA Parameter Optimization
================================================================

Generate publication-ready figures for all optimization analyses:
1. Freshness Time Constants Optimization (5 subplots)
2. Geographic Threshold Sensitivity
3. Threat Penalty Weight Optimization (3D/heatmap)
4. Base Weight Sensitivity Analysis (parallel coordinates)
5. Complete ROC Curve with Threshold Analysis
6. SIEM Weight Optimization (contour plot)

Author: Research Team
Date: 2024
"""

from typing import Dict, List, Tuple

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import cm
from matplotlib.colors import LinearSegmentedColormap
from mpl_toolkits.mplot3d import Axes3D

# Publication settings
plt.rcParams["font.family"] = "serif"
plt.rcParams["font.serif"] = ["Times New Roman"]
plt.rcParams["font.size"] = 10
plt.rcParams["axes.labelsize"] = 11
plt.rcParams["axes.titlesize"] = 12
plt.rcParams["xtick.labelsize"] = 9
plt.rcParams["ytick.labelsize"] = 9
plt.rcParams["legend.fontsize"] = 9
plt.rcParams["figure.titlesize"] = 13
plt.rcParams["figure.dpi"] = 300
plt.rcParams["savefig.dpi"] = 300
plt.rcParams["savefig.bbox"] = "tight"
plt.rcParams["savefig.pad_inches"] = 0.1


class OptimizationVisualizer:
    """Generate publication-ready visualizations for parameter optimization"""

    def __init__(self, optimization_results: Dict, output_dir: str = "figures"):
        """
        Initialize visualizer with optimization results

        Args:
            optimization_results: Results from ParameterOptimizer
            output_dir: Directory to save figures
        """
        self.results = optimization_results
        self.output_dir = output_dir

        # Color schemes
        self.colors = {
            "primary": "#2E86AB",
            "secondary": "#A23B72",
            "accent": "#F18F01",
            "success": "#06A77D",
            "warning": "#D6573B",
            "neutral": "#6C757D",
        }

    def plot_freshness_optimization(self, save_path: str = None):
        """
        Analysis 1: Multi-panel showing F1-Score vs Time Constant for each signal type

        Args:
            save_path: Path to save figure (optional)
        """
        fig, axes = plt.subplots(2, 3, figsize=(13, 8))
        fig.suptitle(
            "Freshness Time Constants Optimization", fontweight="bold", y=0.995
        )

        signal_types = ["gps", "ip", "device", "wifi", "tls"]
        signal_labels = {
            "gps": "GPS Location",
            "ip": "IP Geolocation",
            "device": "Device Posture",
            "wifi": "Wi-Fi BSSID",
            "tls": "TLS Fingerprint",
        }

        for idx, signal_type in enumerate(signal_types):
            row = idx // 3
            col = idx % 3
            ax = axes[row, col]

            result = self.results["freshness"][signal_type]
            df = result["results"]

            # Convert to hours for x-axis
            x_values = df["value_hours"].values
            y_values = df["f1_score"].values

            # Plot curve
            ax.plot(
                x_values,
                y_values,
                linewidth=2,
                color=self.colors["primary"],
                marker="o",
                markersize=4,
                markevery=2,
            )

            # Mark optimal value
            optimal_hours = result["optimal_value"] / 3600
            optimal_f1 = result["optimal_f1"]
            ax.axvline(
                optimal_hours,
                color=self.colors["accent"],
                linestyle="--",
                linewidth=2,
                alpha=0.7,
                label=f"Optimal: {optimal_hours:.2f}h",
            )
            ax.plot(
                optimal_hours,
                optimal_f1,
                "r*",
                markersize=15,
                markeredgecolor="darkred",
                markeredgewidth=1.5,
            )

            # Formatting
            ax.set_xlabel("Time Constant (hours)", fontweight="bold")
            ax.set_ylabel("F1-Score", fontweight="bold")
            ax.set_title(signal_labels[signal_type], fontweight="bold", pad=10)
            ax.grid(True, alpha=0.3, linestyle=":", linewidth=0.8)
            ax.legend(loc="best", framealpha=0.9)
            ax.set_xscale("log")

            # Add annotation
            ax.annotate(
                f"F1 = {optimal_f1:.4f}",
                xy=(optimal_hours, optimal_f1),
                xytext=(10, -15),
                textcoords="offset points",
                bbox=dict(boxstyle="round,pad=0.5", facecolor="yellow", alpha=0.7),
                arrowprops=dict(
                    arrowstyle="->", connectionstyle="arc3,rad=0", color="black", lw=1.5
                ),
                fontsize=8,
                ha="left",
            )

        # Remove empty subplot
        fig.delaxes(axes[1, 2])

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def plot_geographic_threshold(self, save_path: str = None):
        """
        Analysis 2: Geographic threshold (d₀) sensitivity with F1-Score and FPR

        Args:
            save_path: Path to save figure (optional)
        """
        fig, ax1 = plt.subplots(figsize=(6.5, 4))

        result = self.results["geographic"]
        df = result["results"]

        # Primary axis: F1-Score
        color1 = self.colors["primary"]
        ax1.set_xlabel("Geographic Threshold d₀ (km)", fontweight="bold")
        ax1.set_ylabel("F1-Score", color=color1, fontweight="bold")
        line1 = ax1.plot(
            df["value"],
            df["f1_score"],
            linewidth=2.5,
            color=color1,
            marker="o",
            markersize=5,
            markevery=3,
            label="F1-Score",
        )
        ax1.tick_params(axis="y", labelcolor=color1)
        ax1.grid(True, alpha=0.3, linestyle=":", linewidth=0.8)

        # Mark optimal
        optimal_d0 = result["optimal_value"]
        optimal_f1 = result["optimal_f1"]
        ax1.axvline(
            optimal_d0,
            color=self.colors["accent"],
            linestyle="--",
            linewidth=2,
            alpha=0.7,
        )
        ax1.plot(
            optimal_d0,
            optimal_f1,
            "r*",
            markersize=20,
            markeredgecolor="darkred",
            markeredgewidth=2,
        )

        # Secondary axis: FPR
        ax2 = ax1.twinx()
        color2 = self.colors["warning"]
        ax2.set_ylabel("False Positive Rate (FPR)", color=color2, fontweight="bold")
        line2 = ax2.plot(
            df["value"],
            df["fpr"],
            linewidth=2,
            color=color2,
            linestyle="-.",
            marker="s",
            markersize=4,
            markevery=3,
            label="FPR",
        )
        ax2.tick_params(axis="y", labelcolor=color2)

        # Title and annotation
        ax1.set_title(
            "Geographic Consistency Threshold Optimization", fontweight="bold", pad=15
        )

        ax1.annotate(
            f"Optimal: d₀ = {optimal_d0:.0f} km\nF1 = {optimal_f1:.4f}",
            xy=(optimal_d0, optimal_f1),
            xytext=(30, 20),
            textcoords="offset points",
            bbox=dict(
                boxstyle="round,pad=0.7",
                facecolor="lightyellow",
                edgecolor="black",
                linewidth=1.5,
            ),
            arrowprops=dict(
                arrowstyle="->", connectionstyle="arc3,rad=0.3", color="black", lw=2
            ),
            fontsize=9,
            fontweight="bold",
        )

        # Combined legend
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax1.legend(lines, labels, loc="lower right", framealpha=0.95)

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def plot_threat_penalties(self, save_path: str = None):
        """
        Analysis 3: 3D surface plot / heatmap for threat penalty optimization

        Args:
            save_path: Path to save figure (optional)
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
        fig.suptitle(
            "Threat Intelligence Penalty Weight Optimization", fontweight="bold"
        )

        result = self.results["threat_penalties"]
        df = result["results"]

        # Pivot for heatmap
        pivot_data = df.pivot(
            index="tor_penalty", columns="vpn_penalty", values="f1_score"
        )

        # Subplot 1: Heatmap
        im = ax1.imshow(
            pivot_data.values,
            cmap="viridis",
            aspect="auto",
            origin="lower",
            interpolation="bilinear",
        )

        ax1.set_xlabel("VPN Penalty", fontweight="bold")
        ax1.set_ylabel("TOR Penalty", fontweight="bold")
        ax1.set_title("F1-Score Heatmap", fontweight="bold", pad=10)

        # Set ticks
        ax1.set_xticks(np.arange(len(pivot_data.columns)))
        ax1.set_yticks(np.arange(len(pivot_data.index)))
        ax1.set_xticklabels([f"{x:.1f}" for x in pivot_data.columns])
        ax1.set_yticklabels([f"{y:.1f}" for y in pivot_data.index])

        # Colorbar
        cbar = plt.colorbar(im, ax=ax1)
        cbar.set_label("F1-Score", rotation=270, labelpad=20, fontweight="bold")

        # Mark optimal point
        optimal_vpn = result["optimal_vpn"]
        optimal_tor = result["optimal_tor"]
        optimal_f1 = result["optimal_f1"]

        vpn_idx = np.argmin(np.abs(pivot_data.columns - optimal_vpn))
        tor_idx = np.argmin(np.abs(pivot_data.index - optimal_tor))

        ax1.plot(
            vpn_idx,
            tor_idx,
            "r*",
            markersize=25,
            markeredgecolor="white",
            markeredgewidth=2,
        )
        ax1.text(
            vpn_idx,
            tor_idx - 0.5,
            f"({optimal_vpn:.1f}, {optimal_tor:.1f})\nF1={optimal_f1:.4f}",
            ha="center",
            va="top",
            color="white",
            fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="black", alpha=0.7),
        )

        # Subplot 2: Contour plot
        X, Y = np.meshgrid(pivot_data.columns, pivot_data.index)
        contour = ax2.contourf(X, Y, pivot_data.values, levels=15, cmap="plasma")
        contour_lines = ax2.contour(
            X,
            Y,
            pivot_data.values,
            levels=10,
            colors="white",
            linewidths=0.5,
            alpha=0.5,
        )
        ax2.clabel(contour_lines, inline=True, fontsize=7, fmt="%.3f")

        ax2.set_xlabel("VPN Penalty", fontweight="bold")
        ax2.set_ylabel("TOR Penalty", fontweight="bold")
        ax2.set_title("F1-Score Contours", fontweight="bold", pad=10)

        # Mark optimal
        ax2.plot(
            optimal_vpn,
            optimal_tor,
            "r*",
            markersize=25,
            markeredgecolor="white",
            markeredgewidth=2,
        )
        ax2.annotate(
            f"Optimal\n({optimal_vpn:.2f}, {optimal_tor:.2f})",
            xy=(optimal_vpn, optimal_tor),
            xytext=(15, 15),
            textcoords="offset points",
            bbox=dict(
                boxstyle="round,pad=0.5",
                facecolor="yellow",
                edgecolor="red",
                linewidth=2,
            ),
            arrowprops=dict(arrowstyle="->", color="red", lw=2),
            fontsize=9,
            fontweight="bold",
        )

        # Colorbar
        cbar2 = plt.colorbar(contour, ax=ax2)
        cbar2.set_label("F1-Score", rotation=270, labelpad=20, fontweight="bold")

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def plot_signal_weights(self, save_path: str = None):
        """
        Analysis 4: Parallel coordinates / radar chart for signal weight optimization

        Args:
            save_path: Path to save figure (optional)
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
        fig.suptitle("Base Signal Weight Sensitivity Analysis", fontweight="bold")

        result = self.results["signal_weights"]
        df = result["results"]
        optimal_weights = result["optimal_weights"]

        # Subplot 1: Parallel coordinates
        weight_cols = ["W_gps", "W_ip", "W_device", "W_wifi", "W_tls"]

        # Normalize F1 scores for coloring
        f1_normalized = (df["f1_score"] - df["f1_score"].min()) / (
            df["f1_score"].max() - df["f1_score"].min()
        )

        # Plot sample of weight combinations
        sample_size = min(50, len(df))
        sample_indices = np.linspace(0, len(df) - 1, sample_size, dtype=int)

        for idx in sample_indices:
            row = df.iloc[idx]
            weights = [row[col] for col in weight_cols]
            color = cm.viridis(f1_normalized.iloc[idx])
            alpha = 0.3 + 0.4 * f1_normalized.iloc[idx]
            ax1.plot(
                range(len(weight_cols)),
                weights,
                color=color,
                alpha=alpha,
                linewidth=1.5,
            )

        # Highlight optimal
        optimal_vals = [optimal_weights[col] for col in weight_cols]
        ax1.plot(
            range(len(weight_cols)),
            optimal_vals,
            color="red",
            linewidth=3,
            marker="o",
            markersize=10,
            markeredgecolor="darkred",
            markeredgewidth=2,
            label="Optimal",
            zorder=100,
        )

        ax1.set_xticks(range(len(weight_cols)))
        ax1.set_xticklabels(["GPS", "IP", "Device", "WiFi", "TLS"], rotation=0)
        ax1.set_ylabel("Weight Value", fontweight="bold")
        ax1.set_title("Parallel Coordinates Plot", fontweight="bold", pad=10)
        ax1.set_ylim([0, 0.5])
        ax1.grid(True, alpha=0.3, axis="y")
        ax1.legend(loc="upper right")

        # Add colorbar for F1-score
        sm = cm.ScalarMappable(
            cmap="viridis",
            norm=plt.Normalize(vmin=df["f1_score"].min(), vmax=df["f1_score"].max()),
        )
        sm.set_array([])
        cbar = plt.colorbar(sm, ax=ax1, pad=0.02)
        cbar.set_label("F1-Score", rotation=270, labelpad=20, fontweight="bold")

        # Subplot 2: Radar chart
        angles = np.linspace(0, 2 * np.pi, len(weight_cols), endpoint=False).tolist()
        angles += angles[:1]  # Complete the circle

        ax2 = plt.subplot(122, projection="polar")

        # Plot top 10 weight combinations
        top_10 = df.nlargest(10, "f1_score")
        for idx, row in top_10.iterrows():
            weights = [row[col] for col in weight_cols]
            weights += weights[:1]  # Complete the circle
            f1_color = (row["f1_score"] - df["f1_score"].min()) / (
                df["f1_score"].max() - df["f1_score"].min()
            )
            ax2.plot(
                angles, weights, linewidth=1.5, alpha=0.5, color=cm.plasma(f1_color)
            )
            ax2.fill(angles, weights, alpha=0.1, color=cm.plasma(f1_color))

        # Highlight optimal
        optimal_vals = [optimal_weights[col] for col in weight_cols]
        optimal_vals += optimal_vals[:1]
        ax2.plot(
            angles,
            optimal_vals,
            color="red",
            linewidth=3,
            marker="o",
            markersize=8,
            label="Optimal",
        )
        ax2.fill(angles, optimal_vals, color="red", alpha=0.15)

        # Formatting
        ax2.set_xticks(angles[:-1])
        ax2.set_xticklabels(["GPS", "IP", "Device", "WiFi", "TLS"], fontweight="bold")
        ax2.set_ylim(0, 0.5)
        ax2.set_title(
            "Radar Chart (Top 10 Configurations)", fontweight="bold", pad=20, y=1.08
        )
        ax2.grid(True, alpha=0.3)
        ax2.legend(loc="upper right", bbox_to_anchor=(1.3, 1.1))

        # Add optimal values as text
        textstr = "Optimal Weights:\n"
        for col in weight_cols:
            textstr += f"{col.replace('W_', '')}: {optimal_weights[col]:.3f}\n"
        textstr += f"F1: {result['optimal_f1']:.4f}"
        ax2.text(
            0.5,
            -0.25,
            textstr,
            transform=ax2.transAxes,
            fontsize=9,
            verticalalignment="top",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.8),
        )

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def plot_roc_and_thresholds(self, save_path: str = None):
        """
        Analysis 5: ROC curve with threshold markers and F1-threshold inset

        Args:
            save_path: Path to save figure (optional)
        """
        fig = plt.figure(figsize=(10, 6))

        # Main ROC curve
        ax_main = plt.subplot(1, 2, 1)

        result = self.results["risk_thresholds"]
        fpr = result["fpr"]
        tpr = result["tpr"]
        roc_auc = result["roc_auc"]
        optimal_stepup = result["optimal_stepup"]
        optimal_deny = result["optimal_deny"]

        # Plot ROC curve
        ax_main.plot(
            fpr,
            tpr,
            linewidth=3,
            color=self.colors["primary"],
            label=f"ROC Curve (AUC = {roc_auc:.4f})",
        )
        ax_main.plot(
            [0, 1], [0, 1], "k--", linewidth=1.5, alpha=0.5, label="Random Classifier"
        )

        # Find points for step-up and deny thresholds
        stepup_idx = np.argmin(np.abs(result["thresholds"] - optimal_stepup))
        deny_idx = np.argmin(np.abs(result["thresholds"] - optimal_deny))

        # Mark thresholds on ROC
        ax_main.plot(
            fpr[stepup_idx],
            tpr[stepup_idx],
            "go",
            markersize=12,
            markeredgecolor="darkgreen",
            markeredgewidth=2,
            label=f"Step-up (θ={optimal_stepup:.2f})",
        )
        ax_main.plot(
            fpr[deny_idx],
            tpr[deny_idx],
            "ro",
            markersize=12,
            markeredgecolor="darkred",
            markeredgewidth=2,
            label=f"Deny (θ={optimal_deny:.2f})",
        )

        # Annotations
        ax_main.annotate(
            f"FPR={fpr[stepup_idx]:.4f}\nTPR={tpr[stepup_idx]:.4f}",
            xy=(fpr[stepup_idx], tpr[stepup_idx]),
            xytext=(15, -20),
            textcoords="offset points",
            bbox=dict(
                boxstyle="round,pad=0.5",
                facecolor="lightgreen",
                edgecolor="darkgreen",
                linewidth=1.5,
            ),
            arrowprops=dict(arrowstyle="->", color="darkgreen", lw=2),
            fontsize=8,
        )

        ax_main.annotate(
            f"FPR={fpr[deny_idx]:.4f}\nTPR={tpr[deny_idx]:.4f}",
            xy=(fpr[deny_idx], tpr[deny_idx]),
            xytext=(-60, 10),
            textcoords="offset points",
            bbox=dict(
                boxstyle="round,pad=0.5",
                facecolor="lightcoral",
                edgecolor="darkred",
                linewidth=1.5,
            ),
            arrowprops=dict(arrowstyle="->", color="darkred", lw=2),
            fontsize=8,
        )

        ax_main.set_xlabel("False Positive Rate (FPR)", fontweight="bold")
        ax_main.set_ylabel("True Positive Rate (TPR)", fontweight="bold")
        ax_main.set_title(
            "ROC Curve with Decision Thresholds", fontweight="bold", pad=15
        )
        ax_main.grid(True, alpha=0.3, linestyle=":", linewidth=0.8)
        ax_main.legend(loc="lower right", framealpha=0.95)
        ax_main.set_xlim([-0.02, 1.02])
        ax_main.set_ylim([-0.02, 1.02])

        # Subplot: Threshold vs F1-Score
        ax_f1 = plt.subplot(1, 2, 2)

        threshold_range = result["threshold_range"]
        f1_scores = result["f1_scores"]

        ax_f1.plot(
            threshold_range, f1_scores, linewidth=2.5, color=self.colors["secondary"]
        )
        ax_f1.axvline(
            optimal_stepup,
            color="green",
            linestyle="--",
            linewidth=2,
            alpha=0.7,
            label=f"Step-up: {optimal_stepup:.2f}",
        )
        ax_f1.axvline(
            optimal_deny,
            color="red",
            linestyle="--",
            linewidth=2,
            alpha=0.7,
            label=f"Deny: {optimal_deny:.2f}",
        )

        # Mark peaks
        best_f1_threshold = result["best_f1_threshold"]
        best_f1 = result["best_f1"]
        ax_f1.plot(
            best_f1_threshold,
            best_f1,
            "b*",
            markersize=20,
            markeredgecolor="darkblue",
            markeredgewidth=2,
            label=f"Max F1: {best_f1:.4f}",
        )

        ax_f1.set_xlabel("Risk Score Threshold", fontweight="bold")
        ax_f1.set_ylabel("F1-Score", fontweight="bold")
        ax_f1.set_title("Threshold vs F1-Score Analysis", fontweight="bold", pad=15)
        ax_f1.grid(True, alpha=0.3, linestyle=":", linewidth=0.8)
        ax_f1.legend(loc="best", framealpha=0.95)

        # Add threshold regions
        ax_f1.axvspan(0, optimal_stepup, alpha=0.1, color="green", label="Allow Zone")
        ax_f1.axvspan(optimal_stepup, optimal_deny, alpha=0.1, color="yellow")
        ax_f1.axvspan(optimal_deny, 1, alpha=0.1, color="red")

        # Region labels
        ax_f1.text(
            optimal_stepup / 2,
            ax_f1.get_ylim()[1] * 0.95,
            "Allow",
            ha="center",
            va="top",
            fontweight="bold",
            fontsize=10,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgreen", alpha=0.7),
        )
        ax_f1.text(
            (optimal_stepup + optimal_deny) / 2,
            ax_f1.get_ylim()[1] * 0.95,
            "Step-up",
            ha="center",
            va="top",
            fontweight="bold",
            fontsize=10,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow", alpha=0.7),
        )
        ax_f1.text(
            (optimal_deny + 1) / 2,
            ax_f1.get_ylim()[1] * 0.95,
            "Deny",
            ha="center",
            va="top",
            fontweight="bold",
            fontsize=10,
            bbox=dict(boxstyle="round,pad=0.3", facecolor="lightcoral", alpha=0.7),
        )

        plt.suptitle(
            "Complete ROC Analysis with Threshold Optimization",
            fontweight="bold",
            fontsize=14,
            y=0.98,
        )
        plt.tight_layout(rect=[0, 0, 1, 0.96])

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def plot_siem_weights(self, save_path: str = None):
        """
        Analysis 6: Contour plot for SIEM weight optimization

        Args:
            save_path: Path to save figure (optional)
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
        fig.suptitle("SIEM Alert Weight Optimization", fontweight="bold")

        result = self.results["siem_weights"]
        df = result["results"]

        # Pivot for visualization
        pivot_data = df.pivot(
            index="medium_weight", columns="high_weight", values="f1_score"
        )

        # Subplot 1: Filled contour
        X, Y = np.meshgrid(pivot_data.columns, pivot_data.index)
        contour_filled = ax1.contourf(X, Y, pivot_data.values, levels=20, cmap="RdYlGn")
        contour_lines = ax1.contour(
            X,
            Y,
            pivot_data.values,
            levels=10,
            colors="black",
            linewidths=0.8,
            alpha=0.4,
        )
        ax1.clabel(contour_lines, inline=True, fontsize=7, fmt="%.4f")

        ax1.set_xlabel("High-Severity Alert Weight", fontweight="bold")
        ax1.set_ylabel("Medium-Severity Alert Weight", fontweight="bold")
        ax1.set_title("F1-Score Contour Map", fontweight="bold", pad=10)

        # Mark optimal
        optimal_high = result["optimal_high"]
        optimal_medium = result["optimal_medium"]
        optimal_f1 = result["optimal_f1"]

        ax1.plot(
            optimal_high,
            optimal_medium,
            "r*",
            markersize=25,
            markeredgecolor="white",
            markeredgewidth=2.5,
            zorder=100,
        )
        ax1.annotate(
            f"Optimal\nHigh: {optimal_high:.2f}\nMed: {optimal_medium:.2f}\nF1: {optimal_f1:.4f}",
            xy=(optimal_high, optimal_medium),
            xytext=(20, 20),
            textcoords="offset points",
            bbox=dict(
                boxstyle="round,pad=0.7",
                facecolor="yellow",
                edgecolor="red",
                linewidth=2,
            ),
            arrowprops=dict(arrowstyle="->", color="red", lw=2.5),
            fontsize=9,
            fontweight="bold",
        )

        # Colorbar
        cbar1 = plt.colorbar(contour_filled, ax=ax1)
        cbar1.set_label("F1-Score", rotation=270, labelpad=20, fontweight="bold")

        # Subplot 2: Precision vs Recall trade-off
        pivot_precision = df.pivot(
            index="medium_weight", columns="high_weight", values="precision"
        )
        pivot_recall = df.pivot(
            index="medium_weight", columns="high_weight", values="recall"
        )

        # Create trade-off metric
        tradeoff = pivot_precision.values - pivot_recall.values

        im = ax2.imshow(
            tradeoff,
            cmap="RdBu_r",
            aspect="auto",
            origin="lower",
            extent=[
                pivot_data.columns.min(),
                pivot_data.columns.max(),
                pivot_data.index.min(),
                pivot_data.index.max(),
            ],
            interpolation="bilinear",
        )

        ax2.set_xlabel("High-Severity Alert Weight", fontweight="bold")
        ax2.set_ylabel("Medium-Severity Alert Weight", fontweight="bold")
        ax2.set_title("Precision - Recall Trade-off", fontweight="bold", pad=10)

        # Mark optimal
        ax2.plot(
            optimal_high,
            optimal_medium,
            "r*",
            markersize=25,
            markeredgecolor="white",
            markeredgewidth=2.5,
            zorder=100,
        )

        # Colorbar
        cbar2 = plt.colorbar(im, ax=ax2)
        cbar2.set_label(
            "Precision - Recall", rotation=270, labelpad=20, fontweight="bold"
        )

        plt.tight_layout()

        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")

        return fig

    def generate_all_figures(self):
        """
        Generate all 6 optimization figures

        Returns:
            Dictionary mapping figure names to matplotlib figure objects
        """
        import os

        os.makedirs(self.output_dir, exist_ok=True)

        print("=" * 80)
        print("GENERATING PUBLICATION-READY FIGURES")
        print("=" * 80)

        figures = {}

        print("\n[1/6] Generating freshness optimization figure...")
        fig1 = self.plot_freshness_optimization(
            save_path=f"{self.output_dir}/fig1_freshness_optimization.png"
        )
        figures["freshness"] = fig1

        print("\n[2/6] Generating geographic threshold figure...")
        fig2 = self.plot_geographic_threshold(
            save_path=f"{self.output_dir}/fig2_geographic_threshold.png"
        )
        figures["geographic"] = fig2

        print("\n[3/6] Generating threat penalties figure...")
        fig3 = self.plot_threat_penalties(
            save_path=f"{self.output_dir}/fig3_threat_penalties.png"
        )
        figures["threat"] = fig3

        print("\n[4/6] Generating signal weights figure...")
        fig4 = self.plot_signal_weights(
            save_path=f"{self.output_dir}/fig4_signal_weights.png"
        )
        figures["weights"] = fig4

        print("\n[5/6] Generating ROC curve figure...")
        fig5 = self.plot_roc_and_thresholds(
            save_path=f"{self.output_dir}/fig5_roc_thresholds.png"
        )
        figures["roc"] = fig5

        print("\n[6/6] Generating SIEM weights figure...")
        fig6 = self.plot_siem_weights(
            save_path=f"{self.output_dir}/fig6_siem_weights.png"
        )
        figures["siem"] = fig6

        print("\n" + "=" * 80)
        print("ALL FIGURES GENERATED SUCCESSFULLY")
        print("=" * 80)
        print(f"\nFigures saved to: {self.output_dir}/")

        return figures

    def generate_summary_table(self, save_path: str = None) -> pd.DataFrame:
        """
        Generate summary table of optimal values vs tested ranges

        Args:
            save_path: Path to save CSV (optional)

        Returns:
            DataFrame with summary statistics
        """
        summary_data = []

        # Freshness constants
        for signal_type, result in self.results["freshness"].items():
            df = result["results"]
            summary_data.append(
                {
                    "Parameter": f"T_{signal_type}",
                    "Description": f"{signal_type.upper()} Freshness Time",
                    "Optimal Value": f"{result['optimal_value'] / 3600:.2f} hours",
                    "Tested Range": f"{df['value_hours'].min():.2f}-{df['value_hours'].max():.2f} hours",
                    "Optimal F1": f"{result['optimal_f1']:.4f}",
                    "Performance Impact": "High"
                    if result["optimal_f1"] > 0.85
                    else "Medium",
                }
            )

        # Geographic threshold
        geo_result = self.results["geographic"]
        geo_df = geo_result["results"]
        summary_data.append(
            {
                "Parameter": "d₀",
                "Description": "Geographic Consistency Threshold",
                "Optimal Value": f"{geo_result['optimal_value']:.0f} km",
                "Tested Range": f"{geo_df['value'].min():.0f}-{geo_df['value'].max():.0f} km",
                "Optimal F1": f"{geo_result['optimal_f1']:.4f}",
                "Performance Impact": "High",
            }
        )

        # Threat penalties
        threat_result = self.results["threat_penalties"]
        summary_data.append(
            {
                "Parameter": "penalty_vpn",
                "Description": "VPN Detection Penalty",
                "Optimal Value": f"{threat_result['optimal_vpn']:.2f}",
                "Tested Range": "0.10-0.90",
                "Optimal F1": f"{threat_result['optimal_f1']:.4f}",
                "Performance Impact": "Medium",
            }
        )
        summary_data.append(
            {
                "Parameter": "penalty_tor",
                "Description": "TOR Detection Penalty",
                "Optimal Value": f"{threat_result['optimal_tor']:.2f}",
                "Tested Range": "0.10-0.90",
                "Optimal F1": f"{threat_result['optimal_f1']:.4f}",
                "Performance Impact": "High",
            }
        )

        # Signal weights
        weight_result = self.results["signal_weights"]
        for signal in ["gps", "ip", "device", "wifi", "tls"]:
            weight_key = f"W_{signal}"
            summary_data.append(
                {
                    "Parameter": weight_key,
                    "Description": f"{signal.upper()} Signal Weight",
                    "Optimal Value": f"{weight_result['optimal_weights'][weight_key]:.3f}",
                    "Tested Range": "0.000-1.000 (sum=1)",
                    "Optimal F1": f"{weight_result['optimal_f1']:.4f}",
                    "Performance Impact": "Critical",
                }
            )

        # Risk thresholds
        threshold_result = self.results["risk_thresholds"]
        summary_data.append(
            {
                "Parameter": "threshold_stepup",
                "Description": "Step-up Challenge Threshold",
                "Optimal Value": f"{threshold_result['optimal_stepup']:.3f}",
                "Tested Range": "0.000-1.000",
                "Optimal F1": f"{threshold_result['best_f1']:.4f}",
                "Performance Impact": "Critical",
            }
        )
        summary_data.append(
            {
                "Parameter": "threshold_deny",
                "Description": "Access Denial Threshold",
                "Optimal Value": f"{threshold_result['optimal_deny']:.3f}",
                "Tested Range": "0.000-1.000",
                "Optimal F1": f"{threshold_result['best_f1']:.4f}",
                "Performance Impact": "Critical",
            }
        )

        # SIEM weights
        siem_result = self.results["siem_weights"]
        summary_data.append(
            {
                "Parameter": "siem_weight_high",
                "Description": "High-Severity SIEM Weight",
                "Optimal Value": f"{siem_result['optimal_high']:.2f}",
                "Tested Range": "0.10-0.50",
                "Optimal F1": f"{siem_result['optimal_f1']:.4f}",
                "Performance Impact": "Medium",
            }
        )
        summary_data.append(
            {
                "Parameter": "siem_weight_medium",
                "Description": "Medium-Severity SIEM Weight",
                "Optimal Value": f"{siem_result['optimal_medium']:.2f}",
                "Tested Range": "0.05-0.30",
                "Optimal F1": f"{siem_result['optimal_f1']:.4f}",
                "Performance Impact": "Low",
            }
        )

        summary_df = pd.DataFrame(summary_data)

        if save_path:
            summary_df.to_csv(save_path, index=False)
            print(f"\nSummary table saved to: {save_path}")

        return summary_df
