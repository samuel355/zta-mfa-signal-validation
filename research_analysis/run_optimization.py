"""
Main Execution Script for Zero Trust MFA Parameter Optimization
================================================================

This script orchestrates the complete parameter optimization analysis:
1. Generate synthetic authentication dataset
2. Run comprehensive parameter optimization
3. Generate publication-ready visualizations
4. Produce summary statistics and reports

Usage:
    python run_optimization.py

Author: Research Team
Date: 2024
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime

import numpy as np
import pandas as pd

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dataset_generator import DatasetGenerator
from parameter_optimizer import ParameterOptimizer
from visualization import OptimizationVisualizer


def print_header(title: str):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80 + "\n")


def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description="Zero Trust MFA Parameter Optimization Analysis"
    )
    parser.add_argument(
        "--n-sessions",
        type=int,
        default=5000,
        help="Number of authentication sessions to generate (default: 5000)",
    )
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.20,
        help="Proportion of attack sessions (default: 0.20)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="./results",
        help="Output directory for results (default: ./results)",
    )
    parser.add_argument(
        "--seed", type=int, default=42, help="Random seed (default: 42)"
    )
    parser.add_argument(
        "--skip-dataset",
        action="store_true",
        help="Skip dataset generation and use existing data",
    )
    parser.add_argument(
        "--dataset-path",
        type=str,
        default=None,
        help="Path to existing dataset CSV file",
    )

    args = parser.parse_args()

    # Create output directories
    os.makedirs(args.output_dir, exist_ok=True)
    figures_dir = os.path.join(args.output_dir, "figures")
    os.makedirs(figures_dir, exist_ok=True)

    # Start timing
    start_time = time.time()

    print_header("ZERO TRUST MFA PARAMETER OPTIMIZATION ANALYSIS")
    print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output Directory: {args.output_dir}")
    print(f"Random Seed: {args.seed}")

    # =========================================================================
    # STEP 1: Generate or Load Dataset
    # =========================================================================
    print_header("STEP 1: DATASET GENERATION")

    if args.skip_dataset and args.dataset_path:
        print(f"Loading existing dataset from: {args.dataset_path}")
        df = pd.read_csv(args.dataset_path)
        print(f"Loaded {len(df)} sessions")
    else:
        print(f"Generating synthetic authentication dataset...")
        print(f"  Sessions: {args.n_sessions}")
        print(f"  Attack Ratio: {args.attack_ratio:.1%}")

        generator = DatasetGenerator(seed=args.seed)

        df = generator.generate_dataset(
            n_sessions=args.n_sessions,
            attack_ratio=args.attack_ratio,
            attack_distribution={
                "geo_spoof": 0.40,
                "stale_data": 0.30,
                "device_compromise": 0.20,
                "network_manipulation": 0.10,
            },
        )

        # Save dataset
        dataset_path = os.path.join(args.output_dir, "synthetic_dataset.csv")
        df.to_csv(dataset_path, index=False)
        print(f"\nDataset saved to: {dataset_path}")

    # Display dataset statistics
    print("\n" + "-" * 80)
    print("Dataset Statistics:")
    print("-" * 80)
    print(f"Total Sessions: {len(df)}")
    print(f"Features: {len(df.columns)}")
    print(f"\nClass Distribution:")
    print(
        f"  Legitimate: {len(df[~df['is_attack']])} ({100 * len(df[~df['is_attack']]) / len(df):.1f}%)"
    )
    print(
        f"  Attacks: {len(df[df['is_attack']])} ({100 * len(df[df['is_attack']]) / len(df):.1f}%)"
    )

    if df["is_attack"].sum() > 0:
        print(f"\nAttack Type Distribution:")
        attack_counts = df[df["is_attack"]]["attack_type"].value_counts()
        for attack_type, count in attack_counts.items():
            print(
                f"  {attack_type}: {count} ({100 * count / len(df[df['is_attack']]):.1f}%)"
            )

    # =========================================================================
    # STEP 2: Parameter Optimization
    # =========================================================================
    print_header("STEP 2: COMPREHENSIVE PARAMETER OPTIMIZATION")

    optimizer = ParameterOptimizer(df, random_state=args.seed)

    print("Running optimization for all parameters...")
    print("This may take several minutes depending on dataset size.\n")

    optimization_results = optimizer.run_comprehensive_optimization()

    # Get optimal parameters
    optimal_params = optimizer.get_optimal_parameters()

    print("\n" + "-" * 80)
    print("Optimal Parameters Summary:")
    print("-" * 80)
    print("\nFreshness Time Constants:")
    print(f"  T_gps:    {optimal_params['T_gps'] / 60:.1f} minutes")
    print(f"  T_ip:     {optimal_params['T_ip'] / 60:.1f} minutes")
    print(f"  T_device: {optimal_params['T_device'] / 3600:.1f} hours")
    print(f"  T_wifi:   {optimal_params['T_wifi'] / 60:.1f} minutes")
    print(f"  T_tls:    {optimal_params['T_tls'] / 60:.1f} minutes")

    print("\nGeographic Threshold:")
    print(f"  d₀: {optimal_params['d0']:.0f} km")

    print("\nThreat Penalties:")
    print(f"  VPN:       {optimal_params['penalty_vpn']:.2f}")
    print(f"  TOR:       {optimal_params['penalty_tor']:.2f}")
    print(f"  Malicious: {optimal_params['penalty_malicious']:.2f}")
    print(f"  Unknown:   {optimal_params['penalty_unknown']:.2f}")

    print("\nSignal Weights:")
    print(f"  W_gps:    {optimal_params['W_gps']:.3f}")
    print(f"  W_ip:     {optimal_params['W_ip']:.3f}")
    print(f"  W_device: {optimal_params['W_device']:.3f}")
    print(f"  W_wifi:   {optimal_params['W_wifi']:.3f}")
    print(f"  W_tls:    {optimal_params['W_tls']:.3f}")
    print(
        f"  Sum:      {sum([optimal_params[f'W_{s}'] for s in ['gps', 'ip', 'device', 'wifi', 'tls']]):.3f}"
    )

    print("\nRisk Thresholds:")
    print(f"  Step-up: {optimal_params['threshold_stepup']:.3f}")
    print(f"  Deny:    {optimal_params['threshold_deny']:.3f}")

    print("\nSIEM Alert Weights:")
    print(f"  High-severity:   {optimal_params['siem_weight_high']:.2f}")
    print(f"  Medium-severity: {optimal_params['siem_weight_medium']:.2f}")

    # =========================================================================
    # STEP 3: Test Set Evaluation
    # =========================================================================
    print_header("STEP 3: FINAL EVALUATION ON TEST SET")

    test_metrics = optimizer.evaluate_on_test_set(optimal_params)

    # =========================================================================
    # STEP 4: Generate Visualizations
    # =========================================================================
    print_header("STEP 4: GENERATING PUBLICATION-READY VISUALIZATIONS")

    visualizer = OptimizationVisualizer(optimization_results, output_dir=figures_dir)

    figures = visualizer.generate_all_figures()

    print(f"\nAll figures saved to: {figures_dir}/")
    print("\nGenerated figures:")
    print("  1. fig1_freshness_optimization.png - Freshness time constants")
    print("  2. fig2_geographic_threshold.png - Geographic consistency threshold")
    print("  3. fig3_threat_penalties.png - Threat intelligence penalties")
    print("  4. fig4_signal_weights.png - Base signal weights")
    print("  5. fig5_roc_thresholds.png - ROC curve with thresholds")
    print("  6. fig6_siem_weights.png - SIEM alert weights")

    # =========================================================================
    # STEP 5: Generate Summary Reports
    # =========================================================================
    print_header("STEP 5: GENERATING SUMMARY REPORTS")

    # Save optimization results
    optimizer.save_results(args.output_dir)

    # Generate summary table
    summary_table = visualizer.generate_summary_table(
        save_path=os.path.join(args.output_dir, "parameter_summary.csv")
    )

    print("\nParameter Summary Table:")
    print(summary_table.to_string(index=False))

    # Generate comprehensive report
    report_path = os.path.join(args.output_dir, "optimization_report.txt")
    with open(report_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("ZERO TRUST MFA PARAMETER OPTIMIZATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Random Seed: {args.seed}\n")
        f.write(f"Dataset Size: {len(df)} sessions\n")
        f.write(f"Attack Ratio: {args.attack_ratio:.1%}\n\n")

        f.write("-" * 80 + "\n")
        f.write("OPTIMAL PARAMETERS\n")
        f.write("-" * 80 + "\n\n")

        f.write("Freshness Time Constants:\n")
        for signal in ["gps", "ip", "device", "wifi", "tls"]:
            param_key = f"T_{signal}"
            value_sec = optimal_params[param_key]
            if signal == "device":
                f.write(f"  {param_key:10s}: {value_sec / 3600:6.1f} hours\n")
            else:
                f.write(f"  {param_key:10s}: {value_sec / 60:6.1f} minutes\n")

        f.write(f"\nGeographic Threshold:\n")
        f.write(f"  d₀: {optimal_params['d0']:.0f} km\n")

        f.write(f"\nThreat Intelligence Penalties:\n")
        f.write(f"  VPN Detection:       {optimal_params['penalty_vpn']:.2f}\n")
        f.write(f"  TOR Detection:       {optimal_params['penalty_tor']:.2f}\n")
        f.write(f"  Malicious IP:        {optimal_params['penalty_malicious']:.2f}\n")
        f.write(f"  Unknown/Low Rep:     {optimal_params['penalty_unknown']:.2f}\n")

        f.write(f"\nBase Signal Weights:\n")
        for signal in ["gps", "ip", "device", "wifi", "tls"]:
            weight_key = f"W_{signal}"
            f.write(f"  {weight_key:10s}: {optimal_params[weight_key]:.3f}\n")

        f.write(f"\nRisk Score Thresholds:\n")
        f.write(f"  Step-up Challenge: {optimal_params['threshold_stepup']:.3f}\n")
        f.write(f"  Access Denial:     {optimal_params['threshold_deny']:.3f}\n")

        f.write(f"\nSIEM Alert Weights:\n")
        f.write(f"  High-Severity:   {optimal_params['siem_weight_high']:.2f}\n")
        f.write(f"  Medium-Severity: {optimal_params['siem_weight_medium']:.2f}\n")

        f.write("\n" + "-" * 80 + "\n")
        f.write("TEST SET PERFORMANCE\n")
        f.write("-" * 80 + "\n\n")

        f.write(f"F1-Score:        {test_metrics['f1_score']:.4f}\n")
        f.write(f"Precision:       {test_metrics['precision']:.4f}\n")
        f.write(f"Recall:          {test_metrics['recall']:.4f}\n")
        f.write(f"Accuracy:        {test_metrics['accuracy']:.4f}\n")
        f.write(f"ROC-AUC:         {test_metrics['roc_auc']:.4f}\n")
        f.write(f"MCC:             {test_metrics['mcc']:.4f}\n\n")

        f.write(f"Confusion Matrix:\n")
        f.write(f"  True Negatives:  {test_metrics['true_negative']:5d}\n")
        f.write(f"  False Positives: {test_metrics['false_positive']:5d}\n")
        f.write(f"  False Negatives: {test_metrics['false_negative']:5d}\n")
        f.write(f"  True Positives:  {test_metrics['true_positive']:5d}\n\n")

        f.write(f"Error Rates:\n")
        f.write(f"  False Positive Rate: {test_metrics['fpr']:.4f}\n")
        f.write(f"  True Positive Rate:  {test_metrics['tpr']:.4f}\n")

        if "stepup_rate_legitimate" in test_metrics:
            f.write(f"\nUsability Metrics:\n")
            f.write(
                f"  Step-up Challenge Rate (Legitimate): {test_metrics['stepup_rate_legitimate']:.2%}\n"
            )

        f.write("\n" + "-" * 80 + "\n")
        f.write("OPTIMIZATION SUMMARY\n")
        f.write("-" * 80 + "\n\n")

        f.write("Freshness Constants:\n")
        for signal_type, result in optimization_results["freshness"].items():
            f.write(
                f"  {signal_type.upper():8s}: Optimal F1 = {result['optimal_f1']:.4f}\n"
            )

        f.write(
            f"\nGeographic Threshold: Optimal F1 = {optimization_results['geographic']['optimal_f1']:.4f}\n"
        )
        f.write(
            f"Threat Penalties:     Optimal F1 = {optimization_results['threat_penalties']['optimal_f1']:.4f}\n"
        )
        f.write(
            f"Signal Weights:       Optimal F1 = {optimization_results['signal_weights']['optimal_f1']:.4f}\n"
        )
        f.write(
            f"Risk Thresholds:      ROC-AUC = {optimization_results['risk_thresholds']['roc_auc']:.4f}\n"
        )
        f.write(
            f"SIEM Weights:         Optimal F1 = {optimization_results['siem_weights']['optimal_f1']:.4f}\n"
        )

        f.write("\n" + "=" * 80 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 80 + "\n")

    print(f"\nComprehensive report saved to: {report_path}")

    # =========================================================================
    # COMPLETION
    # =========================================================================
    end_time = time.time()
    elapsed_time = end_time - start_time

    print_header("ANALYSIS COMPLETE")

    print(
        f"Total Execution Time: {elapsed_time:.2f} seconds ({elapsed_time / 60:.2f} minutes)"
    )
    print(f"\nAll results saved to: {args.output_dir}/")
    print("\nGenerated files:")
    print(f"  - synthetic_dataset.csv           : Synthetic authentication dataset")
    print(f"  - optimal_parameters.json         : Optimal parameter values")
    print(f"  - optimization_summary.json       : Optimization summary statistics")
    print(f"  - parameter_summary.csv           : Parameter summary table")
    print(f"  - optimization_report.txt         : Comprehensive text report")
    print(f"  - figures/fig1_*.png              : Publication-ready figures (6 total)")

    print("\n" + "=" * 80)
    print("READY FOR PUBLICATION")
    print("=" * 80)
    print("\nAll parameter values have been empirically justified through")
    print("comprehensive optimization analysis with publication-ready visualizations.")
    print("\nUse these results to strengthen the methodology section of your paper!")

    return 0


if __name__ == "__main__":
    sys.exit(main())
