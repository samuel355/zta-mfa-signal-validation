"""
Test Script for Zero Trust MFA Parameter Optimization System
=============================================================

Quick validation test to ensure all modules work correctly.

Usage:
    python3 test_system.py
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    try:
        import matplotlib
        import numpy as np
        import pandas as pd

        matplotlib.use("Agg")  # Non-interactive backend
        import matplotlib.pyplot as plt
        import seaborn as sns
        from sklearn.metrics import f1_score

        print("  ✓ All dependencies imported successfully")
        return True
    except ImportError as e:
        print(f"  ✗ Import error: {e}")
        return False


def test_dataset_generator():
    """Test dataset generation module"""
    print("\nTesting dataset generator...")
    try:
        from dataset_generator import DatasetGenerator

        # Create small test dataset
        generator = DatasetGenerator(seed=42)
        df = generator.generate_dataset(n_sessions=100, attack_ratio=0.20)

        # Validate dataset
        assert len(df) == 100, "Wrong number of sessions"
        assert "is_attack" in df.columns, "Missing is_attack column"
        assert df["is_attack"].sum() == 20, "Wrong number of attacks"

        print(f"  ✓ Generated {len(df)} sessions successfully")
        return True, df
    except Exception as e:
        print(f"  ✗ Dataset generation failed: {e}")
        return False, None


def test_parameter_optimizer(df):
    """Test parameter optimizer module"""
    print("\nTesting parameter optimizer...")
    try:
        from parameter_optimizer import ParameterOptimizer

        # Create optimizer
        optimizer = ParameterOptimizer(df, random_state=42)

        # Test risk score computation
        session = df.iloc[0]
        risk_score = optimizer.compute_risk_score(session, optimizer.default_params)
        assert 0 <= risk_score <= 1, "Risk score out of bounds"

        # Test evaluation
        metrics = optimizer.evaluate_parameters(optimizer.default_params, df)
        assert "f1_score" in metrics, "Missing F1-score"
        assert "precision" in metrics, "Missing precision"
        assert "recall" in metrics, "Missing recall"

        print(f"  ✓ Optimizer working correctly")
        print(f"    - Test F1-Score: {metrics['f1_score']:.4f}")
        print(f"    - Test Precision: {metrics['precision']:.4f}")
        print(f"    - Test Recall: {metrics['recall']:.4f}")
        return True, optimizer
    except Exception as e:
        print(f"  ✗ Optimizer test failed: {e}")
        import traceback

        traceback.print_exc()
        return False, None


def test_visualization(optimizer):
    """Test visualization module"""
    print("\nTesting visualization module...")
    try:
        # Create mock optimization results
        import numpy as np
        import pandas as pd
        from visualization import OptimizationVisualizer

        mock_results = {
            "freshness": {
                "gps": {
                    "optimal_value": 300,
                    "optimal_f1": 0.90,
                    "results": pd.DataFrame(
                        {
                            "value": np.linspace(60, 1800, 10),
                            "value_hours": np.linspace(60, 1800, 10) / 3600,
                            "f1_score": np.random.uniform(0.8, 0.95, 10),
                        }
                    ),
                }
            },
            "geographic": {
                "optimal_value": 1000,
                "optimal_f1": 0.91,
                "results": pd.DataFrame(
                    {
                        "value": np.linspace(100, 2000, 20),
                        "f1_score": np.random.uniform(0.85, 0.92, 20),
                        "fpr": np.random.uniform(0.02, 0.08, 20),
                    }
                ),
            },
            "threat_penalties": {
                "optimal_vpn": 0.7,
                "optimal_tor": 0.9,
                "optimal_f1": 0.92,
                "results": pd.DataFrame(
                    {
                        "vpn_penalty": np.repeat(np.linspace(0.1, 0.9, 5), 5),
                        "tor_penalty": np.tile(np.linspace(0.1, 0.9, 5), 5),
                        "f1_score": np.random.uniform(0.85, 0.93, 25),
                        "precision": np.random.uniform(0.80, 0.95, 25),
                        "recall": np.random.uniform(0.85, 0.95, 25),
                    }
                ),
            },
            "signal_weights": {
                "optimal_weights": {
                    "W_gps": 0.25,
                    "W_ip": 0.20,
                    "W_device": 0.20,
                    "W_wifi": 0.15,
                    "W_tls": 0.20,
                },
                "optimal_f1": 0.91,
                "results": pd.DataFrame(
                    {
                        "W_gps": np.random.uniform(0.1, 0.4, 50),
                        "W_ip": np.random.uniform(0.1, 0.3, 50),
                        "W_device": np.random.uniform(0.1, 0.3, 50),
                        "W_wifi": np.random.uniform(0.05, 0.25, 50),
                        "W_tls": np.random.uniform(0.1, 0.3, 50),
                        "f1_score": np.random.uniform(0.85, 0.93, 50),
                        "precision": np.random.uniform(0.80, 0.95, 50),
                        "recall": np.random.uniform(0.85, 0.95, 50),
                    }
                ),
            },
            "risk_thresholds": {
                "optimal_stepup": 0.25,
                "optimal_deny": 0.75,
                "best_f1_threshold": 0.50,
                "best_f1": 0.92,
                "roc_auc": 0.94,
                "fpr": np.linspace(0, 1, 100),
                "tpr": np.linspace(0, 1, 100) ** 0.5,
                "thresholds": np.linspace(1, 0, 100),
                "threshold_range": np.linspace(0, 1, 100),
                "f1_scores": np.random.uniform(0.7, 0.92, 100),
            },
            "siem_weights": {
                "optimal_high": 0.30,
                "optimal_medium": 0.15,
                "optimal_f1": 0.91,
                "results": pd.DataFrame(
                    {
                        "high_weight": np.repeat(np.linspace(0.1, 0.5, 5), 5),
                        "medium_weight": np.tile(np.linspace(0.05, 0.3, 5), 5),
                        "f1_score": np.random.uniform(0.85, 0.92, 25),
                        "precision": np.random.uniform(0.80, 0.95, 25),
                        "recall": np.random.uniform(0.85, 0.95, 25),
                    }
                ),
            },
        }

        visualizer = OptimizationVisualizer(mock_results, output_dir="./test_figures")

        print("  ✓ Visualizer initialized successfully")
        print("  Note: Full visualization test skipped (would generate large files)")
        return True
    except Exception as e:
        print(f"  ✗ Visualization test failed: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("=" * 80)
    print("ZERO TRUST MFA OPTIMIZATION SYSTEM - VALIDATION TEST")
    print("=" * 80)

    results = []

    # Test 1: Imports
    results.append(("Imports", test_imports()))

    # Test 2: Dataset Generation
    success, df = test_dataset_generator()
    results.append(("Dataset Generation", success))

    if success and df is not None:
        # Test 3: Parameter Optimizer
        success, optimizer = test_parameter_optimizer(df)
        results.append(("Parameter Optimizer", success))

        if success and optimizer is not None:
            # Test 4: Visualization
            results.append(("Visualization", test_visualization(optimizer)))

    # Summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    all_passed = True
    for test_name, passed in results:
        status = "PASS ✓" if passed else "FAIL ✗"
        print(f"{test_name:.<40} {status}")
        if not passed:
            all_passed = False

    print("=" * 80)

    if all_passed:
        print("\n✓ All tests passed! System is ready to use.")
        print("\nNext step: Run the full optimization analysis:")
        print("  python3 run_optimization.py")
        return 0
    else:
        print("\n✗ Some tests failed. Please check the errors above.")
        print("\nTroubleshooting:")
        print(
            "  1. Ensure all dependencies are installed: pip install -r requirements.txt"
        )
        print("  2. Check Python version: python3 --version (requires >= 3.7)")
        print("  3. Review error messages for specific issues")
        return 1


if __name__ == "__main__":
    sys.exit(main())
