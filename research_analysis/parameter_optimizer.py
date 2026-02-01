"""
Parameter Optimizer for Zero Trust MFA Framework
=================================================

Comprehensive optimization analysis for all framework parameters including:
- Freshness time constants (T_s values)
- Geographic consistency threshold (d₀)
- Threat intelligence penalty weights
- Base signal weights (W_i)
- Risk score thresholds
- SIEM alert weights

Author: Research Team
Date: 2024
"""

import json
import warnings
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from scipy.optimize import minimize
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split

warnings.filterwarnings("ignore")


class ParameterOptimizer:
    """
    Optimize all parameters for the Zero Trust MFA framework
    """

    def __init__(self, df: pd.DataFrame, random_state: int = 42):
        """
        Initialize optimizer with dataset

        Args:
            df: DataFrame containing authentication sessions
            random_state: Random seed for reproducibility
        """
        self.df = df
        self.random_state = random_state

        # Split data: 60% train, 20% validation, 20% test
        self.df_train, df_temp = train_test_split(
            df, test_size=0.4, random_state=random_state, stratify=df["is_attack"]
        )
        self.df_val, self.df_test = train_test_split(
            df_temp,
            test_size=0.5,
            random_state=random_state,
            stratify=df_temp["is_attack"],
        )

        print(f"Dataset split:")
        print(f"  Training: {len(self.df_train)} sessions")
        print(f"  Validation: {len(self.df_val)} sessions")
        print(f"  Test: {len(self.df_test)} sessions")

        # Default parameters (to be optimized)
        self.default_params = {
            # Freshness time constants (in seconds)
            "T_gps": 5 * 60,  # 5 minutes
            "T_ip": 10 * 60,  # 10 minutes
            "T_device": 24 * 3600,  # 24 hours
            "T_wifi": 30 * 60,  # 30 minutes
            "T_tls": 20 * 60,  # 20 minutes
            # Geographic threshold
            "d0": 1000,  # km
            # Threat penalties
            "penalty_vpn": 0.7,
            "penalty_tor": 0.9,
            "penalty_malicious": 0.1,
            "penalty_unknown": 0.2,
            # Base signal weights
            "W_gps": 0.25,
            "W_ip": 0.20,
            "W_device": 0.20,
            "W_tls": 0.20,
            "W_wifi": 0.15,
            # Risk thresholds
            "threshold_stepup": 0.25,
            "threshold_deny": 0.75,
            # SIEM weights
            "siem_weight_high": 0.30,
            "siem_weight_medium": 0.15,
        }

        # Store optimization results
        self.optimization_results = {}

    def haversine_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """
        Calculate haversine distance between two points in kilometers

        Args:
            lat1, lon1: First point coordinates
            lat2, lon2: Second point coordinates

        Returns:
            Distance in kilometers
        """
        R = 6371  # Earth radius in km

        lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
        dlat = lat2 - lat1
        dlon = lon2 - lon1

        a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
        c = 2 * np.arctan2(np.sqrt(a), np.sqrt(1 - a))

        return R * c

    def compute_risk_score(
        self, session: pd.Series, params: Dict, current_time: datetime = None
    ) -> float:
        """
        Compute risk score for a session using given parameters

        Args:
            session: Session data
            params: Parameter dictionary
            current_time: Current time (defaults to session timestamp)

        Returns:
            Risk score (0-1, higher = more risky)
        """
        if current_time is None:
            current_time = session["timestamp"]

        risk_components = {}

        # 1. Freshness penalty
        freshness_penalties = {}

        # GPS freshness
        if pd.notna(session["gps_timestamp"]):
            gps_age = (current_time - session["gps_timestamp"]).total_seconds()
            freshness_penalties["gps"] = 1 - np.exp(-gps_age / params["T_gps"])
        else:
            freshness_penalties["gps"] = 1.0  # Missing data = max penalty

        # IP freshness
        if pd.notna(session["ip_timestamp"]):
            ip_age = (current_time - session["ip_timestamp"]).total_seconds()
            freshness_penalties["ip"] = 1 - np.exp(-ip_age / params["T_ip"])
        else:
            freshness_penalties["ip"] = 1.0

        # Device freshness
        if pd.notna(session["device_last_scan"]):
            device_age = (current_time - session["device_last_scan"]).total_seconds()
            freshness_penalties["device"] = 1 - np.exp(-device_age / params["T_device"])
        else:
            freshness_penalties["device"] = 1.0

        # WiFi freshness
        if pd.notna(session["wifi_timestamp"]):
            wifi_age = (current_time - session["wifi_timestamp"]).total_seconds()
            freshness_penalties["wifi"] = 1 - np.exp(-wifi_age / params["T_wifi"])
        else:
            freshness_penalties["wifi"] = 0.5  # WiFi optional, moderate penalty

        # TLS freshness
        if pd.notna(session["tls_timestamp"]):
            tls_age = (current_time - session["tls_timestamp"]).total_seconds()
            freshness_penalties["tls"] = 1 - np.exp(-tls_age / params["T_tls"])
        else:
            freshness_penalties["tls"] = 1.0

        # 2. Geographic consistency
        geo_distance = self.haversine_distance(
            session["gps_lat"],
            session["gps_lon"],
            session["ip_lat"],
            session["ip_lon"],
        )
        geo_penalty = 1 - np.exp(-geo_distance / params["d0"])

        # 3. Device posture
        device_penalty = 1 - session["device_compliance_score"]

        # 4. Threat intelligence
        threat_penalty = 0.0
        if session["ip_is_vpn"]:
            threat_penalty = max(threat_penalty, params["penalty_vpn"])
        if session["ip_is_tor"]:
            threat_penalty = max(threat_penalty, params["penalty_tor"])
        if session["ip_is_malicious"]:
            threat_penalty = max(threat_penalty, params["penalty_malicious"])

        # IP reputation penalty
        reputation_penalty = 1 - session["ip_reputation_score"]

        # 5. SIEM alerts
        siem_penalty = (
            session["siem_alerts_high"] * params["siem_weight_high"]
            + session["siem_alerts_medium"] * params["siem_weight_medium"]
        )
        siem_penalty = min(siem_penalty, 1.0)  # Cap at 1.0

        # Combine all risk components with weights
        weighted_risk = (
            params["W_gps"] * freshness_penalties["gps"]
            + params["W_ip"] * freshness_penalties["ip"]
            + params["W_device"] * freshness_penalties["device"]
            + params["W_wifi"] * freshness_penalties["wifi"]
            + params["W_tls"] * freshness_penalties["tls"]
        )

        # Add geographic and threat penalties
        weighted_risk += 0.2 * geo_penalty
        weighted_risk += 0.15 * device_penalty
        weighted_risk += 0.15 * threat_penalty
        weighted_risk += 0.1 * reputation_penalty
        weighted_risk += 0.1 * siem_penalty

        # Normalize to [0, 1]
        weighted_risk = min(weighted_risk, 1.0)

        return weighted_risk

    def evaluate_parameters(
        self, params: Dict, df: pd.DataFrame = None
    ) -> Dict[str, float]:
        """
        Evaluate parameters on a dataset

        Args:
            params: Parameter dictionary
            df: DataFrame to evaluate on (defaults to validation set)

        Returns:
            Dictionary of performance metrics
        """
        if df is None:
            df = self.df_val

        # Compute risk scores
        risk_scores = []
        for _, session in df.iterrows():
            risk = self.compute_risk_score(session, params)
            risk_scores.append(risk)

        risk_scores = np.array(risk_scores)
        y_true = df["is_attack"].values

        # Binary predictions based on deny threshold
        y_pred = (risk_scores >= params["threshold_deny"]).astype(int)

        # Calculate metrics
        metrics = {
            "f1_score": f1_score(y_true, y_pred, zero_division=0),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall": recall_score(y_true, y_pred, zero_division=0),
            "accuracy": accuracy_score(y_true, y_pred),
            "mcc": matthews_corrcoef(y_true, y_pred),
        }

        # ROC-AUC
        try:
            metrics["roc_auc"] = roc_auc_score(y_true, risk_scores)
        except:
            metrics["roc_auc"] = 0.0

        # Confusion matrix
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        metrics["true_negative"] = tn
        metrics["false_positive"] = fp
        metrics["false_negative"] = fn
        metrics["true_positive"] = tp
        metrics["fpr"] = fp / (fp + tn) if (fp + tn) > 0 else 0
        metrics["tpr"] = tp / (tp + fn) if (tp + fn) > 0 else 0

        # Step-up challenge rate for legitimate users
        legit_sessions = df[~df["is_attack"]]
        if len(legit_sessions) > 0:
            legit_risk_scores = risk_scores[~df["is_attack"].values]
            stepup_rate = np.mean(
                (legit_risk_scores >= params["threshold_stepup"])
                & (legit_risk_scores < params["threshold_deny"])
            )
            metrics["stepup_rate_legitimate"] = stepup_rate

        return metrics

    def optimize_freshness_constants(
        self, signal_type: str, param_name: str, range_values: np.ndarray
    ) -> Dict:
        """
        Optimize a single freshness time constant

        Args:
            signal_type: Type of signal (gps, ip, device, wifi, tls)
            param_name: Parameter name in params dict
            range_values: Array of values to test (in seconds)

        Returns:
            Dictionary with optimization results
        """
        print(f"\nOptimizing {signal_type} freshness constant ({param_name})...")

        results = []
        params = self.default_params.copy()

        for value in range_values:
            params[param_name] = value
            metrics = self.evaluate_parameters(params, self.df_val)
            results.append(
                {
                    "value": value,
                    "value_hours": value / 3600,
                    "f1_score": metrics["f1_score"],
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                    "fpr": metrics["fpr"],
                }
            )

        results_df = pd.DataFrame(results)

        # Find optimal value
        best_idx = results_df["f1_score"].idxmax()
        optimal_value = results_df.loc[best_idx, "value"]
        optimal_f1 = results_df.loc[best_idx, "f1_score"]

        print(
            f"  Optimal {param_name}: {optimal_value:.0f}s ({optimal_value / 3600:.2f}h) with F1={optimal_f1:.4f}"
        )

        return {
            "signal_type": signal_type,
            "param_name": param_name,
            "optimal_value": optimal_value,
            "optimal_f1": optimal_f1,
            "results": results_df,
        }

    def optimize_geographic_threshold(self, range_values: np.ndarray) -> Dict:
        """
        Optimize geographic consistency threshold (d₀)

        Args:
            range_values: Array of distance values to test (in km)

        Returns:
            Dictionary with optimization results
        """
        print(f"\nOptimizing geographic consistency threshold (d₀)...")

        results = []
        params = self.default_params.copy()

        for value in range_values:
            params["d0"] = value
            metrics = self.evaluate_parameters(params, self.df_val)
            results.append(
                {
                    "value": value,
                    "f1_score": metrics["f1_score"],
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                    "fpr": metrics["fpr"],
                }
            )

        results_df = pd.DataFrame(results)

        # Find optimal value
        best_idx = results_df["f1_score"].idxmax()
        optimal_value = results_df.loc[best_idx, "value"]
        optimal_f1 = results_df.loc[best_idx, "f1_score"]

        print(f"  Optimal d₀: {optimal_value:.0f} km with F1={optimal_f1:.4f}")

        return {
            "param_name": "d0",
            "optimal_value": optimal_value,
            "optimal_f1": optimal_f1,
            "results": results_df,
        }

    def optimize_threat_penalties(
        self, vpn_range: np.ndarray, tor_range: np.ndarray
    ) -> Dict:
        """
        Optimize threat intelligence penalty weights

        Args:
            vpn_range: Array of VPN penalty values
            tor_range: Array of TOR penalty values

        Returns:
            Dictionary with optimization results
        """
        print(f"\nOptimizing threat intelligence penalties...")

        results = []
        params = self.default_params.copy()

        for vpn_penalty in vpn_range:
            for tor_penalty in tor_range:
                params["penalty_vpn"] = vpn_penalty
                params["penalty_tor"] = tor_penalty
                metrics = self.evaluate_parameters(params, self.df_val)
                results.append(
                    {
                        "vpn_penalty": vpn_penalty,
                        "tor_penalty": tor_penalty,
                        "f1_score": metrics["f1_score"],
                        "precision": metrics["precision"],
                        "recall": metrics["recall"],
                    }
                )

        results_df = pd.DataFrame(results)

        # Find optimal values
        best_idx = results_df["f1_score"].idxmax()
        optimal_vpn = results_df.loc[best_idx, "vpn_penalty"]
        optimal_tor = results_df.loc[best_idx, "tor_penalty"]
        optimal_f1 = results_df.loc[best_idx, "f1_score"]

        print(
            f"  Optimal VPN penalty: {optimal_vpn:.2f}, TOR penalty: {optimal_tor:.2f} with F1={optimal_f1:.4f}"
        )

        return {
            "optimal_vpn": optimal_vpn,
            "optimal_tor": optimal_tor,
            "optimal_f1": optimal_f1,
            "results": results_df,
        }

    def optimize_signal_weights(self, n_trials: int = 100) -> Dict:
        """
        Optimize base signal weights using random search with simplex constraint

        Args:
            n_trials: Number of random weight combinations to try

        Returns:
            Dictionary with optimization results
        """
        print(f"\nOptimizing base signal weights...")

        results = []
        params = self.default_params.copy()
        np.random.seed(self.random_state)

        for trial in range(n_trials):
            # Generate random weights using Dirichlet distribution (ensures sum=1)
            weights = np.random.dirichlet(np.ones(5))

            params["W_gps"] = weights[0]
            params["W_ip"] = weights[1]
            params["W_device"] = weights[2]
            params["W_wifi"] = weights[3]
            params["W_tls"] = weights[4]

            metrics = self.evaluate_parameters(params, self.df_val)
            results.append(
                {
                    "W_gps": weights[0],
                    "W_ip": weights[1],
                    "W_device": weights[2],
                    "W_wifi": weights[3],
                    "W_tls": weights[4],
                    "f1_score": metrics["f1_score"],
                    "precision": metrics["precision"],
                    "recall": metrics["recall"],
                }
            )

        results_df = pd.DataFrame(results)

        # Find optimal weights
        best_idx = results_df["f1_score"].idxmax()
        optimal_weights = {
            "W_gps": results_df.loc[best_idx, "W_gps"],
            "W_ip": results_df.loc[best_idx, "W_ip"],
            "W_device": results_df.loc[best_idx, "W_device"],
            "W_wifi": results_df.loc[best_idx, "W_wifi"],
            "W_tls": results_df.loc[best_idx, "W_tls"],
        }
        optimal_f1 = results_df.loc[best_idx, "f1_score"]

        print(f"  Optimal weights:")
        for key, val in optimal_weights.items():
            print(f"    {key}: {val:.3f}")
        print(f"  F1-Score: {optimal_f1:.4f}")

        return {
            "optimal_weights": optimal_weights,
            "optimal_f1": optimal_f1,
            "results": results_df,
        }

    def optimize_risk_thresholds(self) -> Dict:
        """
        Optimize risk score thresholds for step-up and deny decisions

        Returns:
            Dictionary with optimization results and ROC curve data
        """
        print(f"\nOptimizing risk score thresholds...")

        params = self.default_params.copy()

        # Compute risk scores
        risk_scores = []
        for _, session in self.df_val.iterrows():
            risk = self.compute_risk_score(session, params)
            risk_scores.append(risk)

        risk_scores = np.array(risk_scores)
        y_true = self.df_val["is_attack"].values

        # Compute ROC curve
        fpr, tpr, thresholds = roc_curve(y_true, risk_scores)
        roc_auc = roc_auc_score(y_true, risk_scores)

        # Find optimal thresholds
        # Step-up threshold: balance between security and usability (target FPR ~0.05)
        stepup_idx = np.argmin(np.abs(fpr - 0.04))
        optimal_stepup = thresholds[stepup_idx]

        # Deny threshold: high TPR with acceptable FPR (target TPR ~0.93)
        deny_idx = np.argmin(np.abs(tpr - 0.93))
        optimal_deny = thresholds[deny_idx]

        # Calculate F1 scores for different thresholds
        threshold_range = np.linspace(0, 1, 100)
        f1_scores = []
        for thresh in threshold_range:
            y_pred = (risk_scores >= thresh).astype(int)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            f1_scores.append(f1)

        # Find threshold with best F1
        best_f1_idx = np.argmax(f1_scores)
        best_f1_threshold = threshold_range[best_f1_idx]
        best_f1 = f1_scores[best_f1_idx]

        print(
            f"  Optimal step-up threshold: {optimal_stepup:.3f} (FPR={fpr[stepup_idx]:.4f})"
        )
        print(f"  Optimal deny threshold: {optimal_deny:.3f} (TPR={tpr[deny_idx]:.4f})")
        print(f"  ROC-AUC: {roc_auc:.4f}")

        return {
            "optimal_stepup": optimal_stepup,
            "optimal_deny": optimal_deny,
            "best_f1_threshold": best_f1_threshold,
            "best_f1": best_f1,
            "roc_auc": roc_auc,
            "fpr": fpr,
            "tpr": tpr,
            "thresholds": thresholds,
            "threshold_range": threshold_range,
            "f1_scores": f1_scores,
            "risk_scores": risk_scores,
            "y_true": y_true,
        }

    def optimize_siem_weights(
        self, high_range: np.ndarray, medium_range: np.ndarray
    ) -> Dict:
        """
        Optimize SIEM alert weights

        Args:
            high_range: Array of high-severity weight values
            medium_range: Array of medium-severity weight values

        Returns:
            Dictionary with optimization results
        """
        print(f"\nOptimizing SIEM alert weights...")

        results = []
        params = self.default_params.copy()

        for high_weight in high_range:
            for medium_weight in medium_range:
                params["siem_weight_high"] = high_weight
                params["siem_weight_medium"] = medium_weight
                metrics = self.evaluate_parameters(params, self.df_val)
                results.append(
                    {
                        "high_weight": high_weight,
                        "medium_weight": medium_weight,
                        "f1_score": metrics["f1_score"],
                        "precision": metrics["precision"],
                        "recall": metrics["recall"],
                    }
                )

        results_df = pd.DataFrame(results)

        # Find optimal values
        best_idx = results_df["f1_score"].idxmax()
        optimal_high = results_df.loc[best_idx, "high_weight"]
        optimal_medium = results_df.loc[best_idx, "medium_weight"]
        optimal_f1 = results_df.loc[best_idx, "f1_score"]

        print(
            f"  Optimal high-severity weight: {optimal_high:.2f}, medium-severity weight: {optimal_medium:.2f} with F1={optimal_f1:.4f}"
        )

        return {
            "optimal_high": optimal_high,
            "optimal_medium": optimal_medium,
            "optimal_f1": optimal_f1,
            "results": results_df,
        }

    def run_comprehensive_optimization(self) -> Dict:
        """
        Run comprehensive optimization for all parameters

        Returns:
            Dictionary with all optimization results
        """
        print("=" * 80)
        print("COMPREHENSIVE PARAMETER OPTIMIZATION")
        print("=" * 80)

        results = {}

        # 1. Optimize freshness time constants
        print("\n[1/6] Optimizing Freshness Time Constants")
        print("-" * 80)

        freshness_ranges = {
            "gps": (
                "T_gps",
                np.logspace(np.log10(60), np.log10(30 * 60), 20),
            ),  # 1-30 min
            "ip": (
                "T_ip",
                np.logspace(np.log10(60), np.log10(60 * 60), 20),
            ),  # 1-60 min
            "device": (
                "T_device",
                np.logspace(np.log10(3600), np.log10(72 * 3600), 20),
            ),  # 1-72 hours
            "wifi": (
                "T_wifi",
                np.logspace(np.log10(60), np.log10(120 * 60), 20),
            ),  # 1-120 min
            "tls": (
                "T_tls",
                np.logspace(np.log10(60), np.log10(60 * 60), 20),
            ),  # 1-60 min
        }

        results["freshness"] = {}
        for signal_type, (param_name, range_vals) in freshness_ranges.items():
            result = self.optimize_freshness_constants(
                signal_type, param_name, range_vals
            )
            results["freshness"][signal_type] = result

        # 2. Optimize geographic threshold
        print("\n[2/6] Optimizing Geographic Consistency Threshold")
        print("-" * 80)
        d0_range = np.linspace(100, 2000, 40)  # 100-2000 km
        results["geographic"] = self.optimize_geographic_threshold(d0_range)

        # 3. Optimize threat penalties
        print("\n[3/6] Optimizing Threat Intelligence Penalties")
        print("-" * 80)
        vpn_range = np.linspace(0.1, 0.9, 9)
        tor_range = np.linspace(0.1, 0.9, 9)
        results["threat_penalties"] = self.optimize_threat_penalties(
            vpn_range, tor_range
        )

        # 4. Optimize signal weights
        print("\n[4/6] Optimizing Base Signal Weights")
        print("-" * 80)
        results["signal_weights"] = self.optimize_signal_weights(n_trials=200)

        # 5. Optimize risk thresholds
        print("\n[5/6] Optimizing Risk Score Thresholds")
        print("-" * 80)
        results["risk_thresholds"] = self.optimize_risk_thresholds()

        # 6. Optimize SIEM weights
        print("\n[6/6] Optimizing SIEM Alert Weights")
        print("-" * 80)
        high_range = np.linspace(0.1, 0.5, 9)
        medium_range = np.linspace(0.05, 0.3, 9)
        results["siem_weights"] = self.optimize_siem_weights(high_range, medium_range)

        # Store results
        self.optimization_results = results

        print("\n" + "=" * 80)
        print("OPTIMIZATION COMPLETE")
        print("=" * 80)

        return results

    def get_optimal_parameters(self) -> Dict:
        """
        Extract optimal parameters from optimization results

        Returns:
            Dictionary of optimal parameter values
        """
        if not self.optimization_results:
            raise ValueError(
                "Run optimization first using run_comprehensive_optimization()"
            )

        optimal = self.default_params.copy()

        # Update with optimal values
        for signal_type, result in self.optimization_results["freshness"].items():
            optimal[result["param_name"]] = result["optimal_value"]

        optimal["d0"] = self.optimization_results["geographic"]["optimal_value"]

        optimal["penalty_vpn"] = self.optimization_results["threat_penalties"][
            "optimal_vpn"
        ]
        optimal["penalty_tor"] = self.optimization_results["threat_penalties"][
            "optimal_tor"
        ]

        for key, val in self.optimization_results["signal_weights"][
            "optimal_weights"
        ].items():
            optimal[key] = val

        optimal["threshold_stepup"] = self.optimization_results["risk_thresholds"][
            "optimal_stepup"
        ]
        optimal["threshold_deny"] = self.optimization_results["risk_thresholds"][
            "optimal_deny"
        ]

        optimal["siem_weight_high"] = self.optimization_results["siem_weights"][
            "optimal_high"
        ]
        optimal["siem_weight_medium"] = self.optimization_results["siem_weights"][
            "optimal_medium"
        ]

        return optimal

    def evaluate_on_test_set(self, params: Dict = None) -> Dict[str, float]:
        """
        Evaluate final parameters on held-out test set

        Args:
            params: Parameters to evaluate (defaults to optimal parameters)

        Returns:
            Dictionary of test set performance metrics
        """
        if params is None:
            params = self.get_optimal_parameters()

        print("\n" + "=" * 80)
        print("FINAL EVALUATION ON TEST SET")
        print("=" * 80)

        metrics = self.evaluate_parameters(params, self.df_test)

        print(f"\nTest Set Performance:")
        print(f"  F1-Score:  {metrics['f1_score']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  ROC-AUC:   {metrics['roc_auc']:.4f}")
        print(f"  MCC:       {metrics['mcc']:.4f}")
        print(f"\nConfusion Matrix:")
        print(
            f"  TN: {metrics['true_negative']:4d}  FP: {metrics['false_positive']:4d}"
        )
        print(
            f"  FN: {metrics['false_negative']:4d}  TP: {metrics['true_positive']:4d}"
        )
        print(f"\nError Rates:")
        print(f"  FPR: {metrics['fpr']:.4f} (False Positive Rate)")
        print(f"  TPR: {metrics['tpr']:.4f} (True Positive Rate)")
        if "stepup_rate_legitimate" in metrics:
            print(f"\nUsability:")
            print(
                f"  Step-up challenge rate for legitimate users: {metrics['stepup_rate_legitimate']:.2%}"
            )

        return metrics

    def save_results(self, output_dir: str):
        """
        Save optimization results to files

        Args:
            output_dir: Directory to save results
        """
        import os

        os.makedirs(output_dir, exist_ok=True)

        # Save optimal parameters
        optimal_params = self.get_optimal_parameters()
        with open(f"{output_dir}/optimal_parameters.json", "w") as f:
            # Convert numpy types to native Python types
            params_serializable = {}
            for key, val in optimal_params.items():
                if isinstance(val, (np.integer, np.floating)):
                    params_serializable[key] = float(val)
                else:
                    params_serializable[key] = val
            json.dump(params_serializable, f, indent=2)

        # Save detailed results
        results_summary = {
            "freshness_constants": {},
            "geographic_threshold": {},
            "threat_penalties": {},
            "signal_weights": {},
            "risk_thresholds": {},
            "siem_weights": {},
        }

        # Populate summary
        for signal_type, result in self.optimization_results["freshness"].items():
            results_summary["freshness_constants"][signal_type] = {
                "optimal_value_seconds": float(result["optimal_value"]),
                "optimal_value_hours": float(result["optimal_value"] / 3600),
                "optimal_f1": float(result["optimal_f1"]),
            }

        results_summary["geographic_threshold"] = {
            "optimal_value_km": float(
                self.optimization_results["geographic"]["optimal_value"]
            ),
            "optimal_f1": float(self.optimization_results["geographic"]["optimal_f1"]),
        }

        results_summary["threat_penalties"] = {
            "optimal_vpn": float(
                self.optimization_results["threat_penalties"]["optimal_vpn"]
            ),
            "optimal_tor": float(
                self.optimization_results["threat_penalties"]["optimal_tor"]
            ),
            "optimal_f1": float(
                self.optimization_results["threat_penalties"]["optimal_f1"]
            ),
        }

        results_summary["signal_weights"] = {
            key: float(val)
            for key, val in self.optimization_results["signal_weights"][
                "optimal_weights"
            ].items()
        }
        results_summary["signal_weights"]["optimal_f1"] = float(
            self.optimization_results["signal_weights"]["optimal_f1"]
        )

        results_summary["risk_thresholds"] = {
            "optimal_stepup": float(
                self.optimization_results["risk_thresholds"]["optimal_stepup"]
            ),
            "optimal_deny": float(
                self.optimization_results["risk_thresholds"]["optimal_deny"]
            ),
            "roc_auc": float(self.optimization_results["risk_thresholds"]["roc_auc"]),
        }

        results_summary["siem_weights"] = {
            "optimal_high": float(
                self.optimization_results["siem_weights"]["optimal_high"]
            ),
            "optimal_medium": float(
                self.optimization_results["siem_weights"]["optimal_medium"]
            ),
            "optimal_f1": float(
                self.optimization_results["siem_weights"]["optimal_f1"]
            ),
        }

        with open(f"{output_dir}/optimization_summary.json", "w") as f:
            json.dump(results_summary, f, indent=2)

        print(f"\nResults saved to {output_dir}/")
        print(f"  - optimal_parameters.json")
        print(f"  - optimization_summary.json")
