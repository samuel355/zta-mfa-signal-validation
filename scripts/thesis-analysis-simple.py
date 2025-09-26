#!/usr/bin/env python3
"""
Simplified Thesis Results Analysis Script (No SciPy dependency)
Multi-Source MFA Zero Trust Architecture Framework

This script generates comprehensive analysis reports for the thesis results chapter,
including basic statistical comparisons, visualizations, and formatted tables.
"""

import json
import os
import sys
import logging
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns
import requests
import psycopg2
from psycopg2.extras import RealDictCursor
from jinja2 import Template
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Set plot style
plt.style.use('default')
sns.set_palette("husl")

class SimpleThesisAnalyzer:
    """Main class for simplified thesis results analysis"""

    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.db_connection = None
        self.results_data = {}
        self.output_dir = config.get('OUTPUT_DIR', './thesis-results')

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def connect_database(self):
        """Connect to PostgreSQL database"""
        try:
            self.db_connection = psycopg2.connect(
                self.config.get('DB_DSN', 'postgresql://postgres:password@localhost:5432/zta_framework'),
                cursor_factory=RealDictCursor
            )
            logger.info("Database connection established")
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def get_metrics_from_api(self, endpoint: str, hours: int = 24) -> Dict[str, Any]:
        """Get metrics data from the metrics API"""
        try:
            metrics_url = self.config.get('METRICS_URL', 'http://localhost:8030')
            response = requests.get(
                f"{metrics_url}/{endpoint}?hours={hours}",
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"API request failed: {response.status_code}")
                return {}

        except Exception as e:
            logger.error(f"Error getting metrics from API: {e}")
            return {}

    def collect_comprehensive_data(self, hours: int = 168) -> Dict[str, Any]:
        """Collect comprehensive data for analysis (default: 7 days)"""
        logger.info(f"Collecting comprehensive data for {hours} hours")

        data = {
            'collection_timestamp': datetime.utcnow().isoformat(),
            'analysis_period_hours': hours,
            'security_accuracy': {},
            'performance_metrics': {},
            'usability_indicators': {},
            'privacy_metrics': {},
            'failed_login_attempts': {},
            'raw_data': {}
        }

        # Collect data from different endpoints
        endpoints = [
            ('thesis/security-accuracy', 'security_accuracy'),
            ('thesis/performance', 'performance_metrics'),
            ('thesis/usability', 'usability_indicators'),
            ('thesis/privacy', 'privacy_metrics'),
            ('thesis/failed-logins', 'failed_login_attempts'),
            ('thesis/comprehensive', 'comprehensive')
        ]

        for endpoint, key in endpoints:
            logger.info(f"Collecting {key} data...")
            result = self.get_metrics_from_api(endpoint, hours)
            if result:
                data[key] = result
            else:
                logger.warning(f"No data collected for {key}")

        # Store raw database queries for detailed analysis
        if self.db_connection:
            data['raw_data'] = self._collect_raw_database_data(hours)

        self.results_data = data
        return data

    def _collect_raw_database_data(self, hours: int) -> Dict[str, Any]:
        """Collect raw data from database for detailed analysis"""
        raw_data = {}

        try:
            with self.db_connection.cursor() as cursor:
                # Framework comparison raw data
                cursor.execute("""
                    SELECT framework_type, decision, risk_score, processing_time_ms, created_at
                    FROM zta.framework_comparison
                    WHERE created_at > NOW() - INTERVAL %s HOUR
                    ORDER BY created_at DESC
                """, (hours,))

                framework_data = cursor.fetchall()
                raw_data['framework_comparison'] = [dict(row) for row in framework_data]

                # Performance metrics raw data
                cursor.execute("""
                    SELECT service_name, operation, duration_ms, status, created_at
                    FROM zta.performance_metrics
                    WHERE created_at > NOW() - INTERVAL %s HOUR
                    AND operation = 'decision'
                    ORDER BY created_at DESC
                """, (hours,))

                performance_data = cursor.fetchall()
                raw_data['performance_metrics'] = [dict(row) for row in performance_data]

                # Security classifications raw data
                cursor.execute("""
                    SELECT framework_type, false_positive, false_negative,
                           classification_accuracy, created_at
                    FROM zta.security_classifications
                    WHERE created_at > NOW() - INTERVAL %s HOUR
                    ORDER BY created_at DESC
                """, (hours,))

                security_data = cursor.fetchall()
                raw_data['security_classifications'] = [dict(row) for row in security_data]

        except Exception as e:
            logger.error(f"Error collecting raw database data: {e}")

        return raw_data

    def calculate_basic_statistics(self) -> Dict[str, Dict[str, Any]]:
        """Calculate basic statistical comparisons (without scipy)"""
        logger.info("Calculating basic statistical comparisons")

        if not self.results_data or 'raw_data' not in self.results_data:
            logger.error("No raw data available for statistical analysis")
            return {}

        results = {}
        raw_data = self.results_data['raw_data']

        # Latency comparison
        if 'framework_comparison' in raw_data:
            df = pd.DataFrame(raw_data['framework_comparison'])
            if not df.empty and 'processing_time_ms' in df.columns:
                baseline_latency = df[df['framework_type'] == 'baseline']['processing_time_ms'].dropna()
                proposed_latency = df[df['framework_type'] == 'proposed']['processing_time_ms'].dropna()

                if len(baseline_latency) > 0 and len(proposed_latency) > 0:
                    # Basic statistics without t-test
                    baseline_mean = float(baseline_latency.mean())
                    proposed_mean = float(proposed_latency.mean())
                    baseline_std = float(baseline_latency.std())
                    proposed_std = float(proposed_latency.std())

                    # Calculate improvement percentage
                    improvement_pct = ((baseline_mean - proposed_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

                    # Simple comparison (difference in means relative to pooled standard deviation)
                    pooled_std = np.sqrt((baseline_std**2 + proposed_std**2) / 2)
                    effect_size = (proposed_mean - baseline_mean) / pooled_std if pooled_std > 0 else 0

                    results['latency'] = {
                        'baseline_mean': baseline_mean,
                        'proposed_mean': proposed_mean,
                        'baseline_std': baseline_std,
                        'proposed_std': proposed_std,
                        'improvement_pct': improvement_pct,
                        'effect_size': effect_size,
                        'sample_sizes': {'baseline': len(baseline_latency), 'proposed': len(proposed_latency)}
                    }

        # Security accuracy comparison
        if 'security_classifications' in raw_data:
            df = pd.DataFrame(raw_data['security_classifications'])
            if not df.empty and 'classification_accuracy' in df.columns:
                baseline_accuracy = df[df['framework_type'] == 'baseline']['classification_accuracy'].dropna()
                proposed_accuracy = df[df['framework_type'] == 'proposed']['classification_accuracy'].dropna()

                if len(baseline_accuracy) > 0 and len(proposed_accuracy) > 0:
                    baseline_mean = float(baseline_accuracy.mean())
                    proposed_mean = float(proposed_accuracy.mean())
                    baseline_std = float(baseline_accuracy.std())
                    proposed_std = float(proposed_accuracy.std())

                    improvement_pct = ((proposed_mean - baseline_mean) / baseline_mean) * 100 if baseline_mean > 0 else 0

                    pooled_std = np.sqrt((baseline_std**2 + proposed_std**2) / 2)
                    effect_size = (proposed_mean - baseline_mean) / pooled_std if pooled_std > 0 else 0

                    results['accuracy'] = {
                        'baseline_mean': baseline_mean,
                        'proposed_mean': proposed_mean,
                        'baseline_std': baseline_std,
                        'proposed_std': proposed_std,
                        'improvement_pct': improvement_pct,
                        'effect_size': effect_size,
                        'sample_sizes': {'baseline': len(baseline_accuracy), 'proposed': len(proposed_accuracy)}
                    }

        return results

    def generate_visualizations(self) -> Dict[str, str]:
        """Generate visualizations for thesis results"""
        logger.info("Generating visualizations")

        if not self.results_data:
            logger.error("No data available for visualization")
            return {}

        viz_files = {}

        # 1. Security Accuracy Metrics Comparison
        if 'security_accuracy' in self.results_data:
            viz_files['security_accuracy'] = self._plot_security_accuracy()

        # 2. Performance Metrics Comparison
        if 'performance_metrics' in self.results_data:
            viz_files['performance'] = self._plot_performance_metrics()

        # 3. Latency Distribution
        if 'raw_data' in self.results_data and 'framework_comparison' in self.results_data['raw_data']:
            viz_files['latency_distribution'] = self._plot_latency_distribution()

        # 4. Usability Metrics
        if 'usability_indicators' in self.results_data:
            viz_files['usability'] = self._plot_usability_metrics()

        # 5. Privacy Metrics
        if 'privacy_metrics' in self.results_data:
            viz_files['privacy'] = self._plot_privacy_metrics()

        # 6. Overview Comparison
        viz_files['overview'] = self._plot_overview_comparison()

        return viz_files

    def _plot_security_accuracy(self) -> str:
        """Plot security accuracy metrics comparison"""
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        fig.suptitle('Security Accuracy Metrics: Proposed vs Baseline Framework', fontsize=16, fontweight='bold')

        metrics = ['tpr', 'fpr', 'precision', 'recall', 'f1_score', 'accuracy']
        metric_labels = ['True Positive Rate', 'False Positive Rate', 'Precision', 'Recall', 'F1-Score', 'Accuracy']

        data = self.results_data.get('security_accuracy', {})

        frameworks = list(data.keys()) if data else []
        if len(frameworks) >= 2:
            baseline_values = [data.get('baseline', {}).get(metric, 0) for metric in metrics]
            proposed_values = [data.get('proposed', {}).get(metric, 0) for metric in metrics]

            for i, (metric, label) in enumerate(zip(metrics, metric_labels)):
                ax = axes[i // 3, i % 3]

                values = [baseline_values[i], proposed_values[i]]
                colors = ['#FF6B6B', '#4ECDC4']
                bars = ax.bar(['Baseline', 'Proposed'], values, color=colors, alpha=0.7)

                ax.set_title(label, fontweight='bold')
                ax.set_ylabel('Score')
                ax.set_ylim(0, 1)
                ax.grid(True, alpha=0.3)

                # Add value labels on bars
                for bar, value in zip(bars, values):
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                           f'{value:.3f}', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'security_accuracy_comparison.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def _plot_performance_metrics(self) -> str:
        """Plot performance metrics comparison"""
        fig, axes = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('Performance Metrics: Proposed vs Baseline Framework', fontsize=16, fontweight='bold')

        data = self.results_data.get('performance_metrics', {})

        if 'baseline' in data and 'proposed' in data:
            baseline = data['baseline']
            proposed = data['proposed']

            # Latency comparison
            ax1 = axes[0, 0]
            latency_metrics = ['avg_latency_ms', 'p95_latency_ms']
            baseline_latency = [baseline.get('avg_latency_ms', 0), baseline.get('p95_latency_ms', 0)]
            proposed_latency = [proposed.get('avg_latency_ms', 0), proposed.get('p95_latency_ms', 0)]

            x = np.arange(len(latency_metrics))
            width = 0.35

            ax1.bar(x - width/2, baseline_latency, width, label='Baseline', color='#FF6B6B', alpha=0.7)
            ax1.bar(x + width/2, proposed_latency, width, label='Proposed', color='#4ECDC4', alpha=0.7)
            ax1.set_title('Decision Latency Comparison')
            ax1.set_ylabel('Latency (ms)')
            ax1.set_xticks(x)
            ax1.set_xticklabels(['Avg Latency', '95th Percentile'])
            ax1.legend()
            ax1.grid(True, alpha=0.3)

            # Throughput comparison
            ax2 = axes[0, 1]
            throughput_values = [baseline.get('throughput_rps', 0), proposed.get('throughput_rps', 0)]
            bars = ax2.bar(['Baseline', 'Proposed'], throughput_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax2.set_title('Throughput Comparison')
            ax2.set_ylabel('Requests/Second')
            ax2.grid(True, alpha=0.3)

            for bar, value in zip(bars, throughput_values):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(throughput_values) * 0.02,
                        f'{value:.1f}', ha='center', va='bottom', fontweight='bold')

            # Resource utilization
            ax3 = axes[1, 0]
            cpu_values = [baseline.get('cpu_utilization_pct', 0), proposed.get('cpu_utilization_pct', 0)]
            bars = ax3.bar(['Baseline', 'Proposed'], cpu_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax3.set_title('CPU Utilization')
            ax3.set_ylabel('CPU %')
            ax3.grid(True, alpha=0.3)

            for bar, value in zip(bars, cpu_values):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(cpu_values) * 0.02,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

            ax4 = axes[1, 1]
            memory_values = [baseline.get('memory_utilization_mb', 0), proposed.get('memory_utilization_mb', 0)]
            bars = ax4.bar(['Baseline', 'Proposed'], memory_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax4.set_title('Memory Utilization')
            ax4.set_ylabel('Memory (MB)')
            ax4.grid(True, alpha=0.3)

            for bar, value in zip(bars, memory_values):
                ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(memory_values) * 0.02,
                        f'{value:.0f}', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'performance_metrics_comparison.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def _plot_latency_distribution(self) -> str:
        """Plot latency distribution histogram"""
        fig, ax = plt.subplots(1, 1, figsize=(10, 6))

        raw_data = self.results_data['raw_data']['framework_comparison']
        df = pd.DataFrame(raw_data)

        if not df.empty and 'processing_time_ms' in df.columns:
            baseline_latency = df[df['framework_type'] == 'baseline']['processing_time_ms'].dropna()
            proposed_latency = df[df['framework_type'] == 'proposed']['processing_time_ms'].dropna()

            if len(baseline_latency) > 0 and len(proposed_latency) > 0:
                ax.hist(baseline_latency, bins=30, alpha=0.7, label='Baseline', color='#FF6B6B', density=True)
                ax.hist(proposed_latency, bins=30, alpha=0.7, label='Proposed', color='#4ECDC4', density=True)

                ax.set_xlabel('Decision Latency (ms)')
                ax.set_ylabel('Density')
                ax.set_title('Decision Latency Distribution Comparison', fontsize=14, fontweight='bold')
                ax.legend()
                ax.grid(True, alpha=0.3)

                # Add statistics text
                stats_text = f"""Baseline: μ={baseline_latency.mean():.1f}ms, σ={baseline_latency.std():.1f}ms
Proposed: μ={proposed_latency.mean():.1f}ms, σ={proposed_latency.std():.1f}ms"""
                ax.text(0.02, 0.98, stats_text, transform=ax.transAxes,
                       verticalalignment='top', bbox=dict(boxstyle='round', facecolor='white', alpha=0.8))

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'latency_distribution.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def _plot_usability_metrics(self) -> str:
        """Plot usability metrics comparison"""
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.suptitle('Usability Indicators: Proposed vs Baseline Framework', fontsize=16, fontweight='bold')

        data = self.results_data.get('usability_indicators', {})

        if 'baseline' in data and 'proposed' in data:
            baseline = data['baseline']
            proposed = data['proposed']

            # Step-up Challenge Rate
            ax1 = axes[0]
            stepup_values = [baseline.get('step_up_challenge_rate_pct', 0), proposed.get('step_up_challenge_rate_pct', 0)]
            bars = ax1.bar(['Baseline', 'Proposed'], stepup_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax1.set_title('Step-up Challenge Rate')
            ax1.set_ylabel('Percentage (%)')
            ax1.grid(True, alpha=0.3)

            for bar, value in zip(bars, stepup_values):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(stepup_values) * 0.02,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

            # User Friction Index
            ax2 = axes[1]
            friction_values = [baseline.get('user_friction_index', 0), proposed.get('user_friction_index', 0)]
            bars = ax2.bar(['Baseline', 'Proposed'], friction_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax2.set_title('User Friction Index')
            ax2.set_ylabel('Friction Score')
            ax2.grid(True, alpha=0.3)

            for bar, value in zip(bars, friction_values):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(friction_values) * 0.02,
                        f'{value:.1f}', ha='center', va='bottom', fontweight='bold')

            # Session Continuity
            ax3 = axes[2]
            continuity_values = [baseline.get('session_continuity_pct', 0), proposed.get('session_continuity_pct', 0)]
            bars = ax3.bar(['Baseline', 'Proposed'], continuity_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax3.set_title('Session Continuity')
            ax3.set_ylabel('Percentage (%)')
            ax3.grid(True, alpha=0.3)

            for bar, value in zip(bars, continuity_values):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(continuity_values) * 0.02,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'usability_metrics_comparison.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def _plot_privacy_metrics(self) -> str:
        """Plot privacy metrics comparison"""
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        fig.suptitle('Privacy Preserving Metrics: Proposed vs Baseline Framework', fontsize=16, fontweight='bold')

        data = self.results_data.get('privacy_metrics', {})

        if 'baseline' in data and 'proposed' in data:
            baseline = data['baseline']
            proposed = data['proposed']

            # Data Minimization Compliance
            ax1 = axes[0]
            compliance_values = [baseline.get('data_minimization_compliance_pct', 0),
                               proposed.get('data_minimization_compliance_pct', 0)]
            bars = ax1.bar(['Baseline', 'Proposed'], compliance_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax1.set_title('Data Minimization Compliance')
            ax1.set_ylabel('Percentage (%)')
            ax1.set_ylim(0, 100)
            ax1.grid(True, alpha=0.3)

            for bar, value in zip(bars, compliance_values):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

            # Privacy Leakage Rate
            ax2 = axes[1]
            leakage_values = [baseline.get('privacy_leakage_rate_pct', 0),
                            proposed.get('privacy_leakage_rate_pct', 0)]
            bars = ax2.bar(['Baseline', 'Proposed'], leakage_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax2.set_title('Privacy Leakage Rate')
            ax2.set_ylabel('Percentage (%)')
            ax2.grid(True, alpha=0.3)

            for bar, value in zip(bars, leakage_values):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(leakage_values) * 0.05,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

            # Signal Retention Duration
            ax3 = axes[2]
            retention_values = [baseline.get('avg_signal_retention_days', 0),
                              proposed.get('avg_signal_retention_days', 0)]
            bars = ax3.bar(['Baseline', 'Proposed'], retention_values, color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax3.set_title('Avg Signal Retention')
            ax3.set_ylabel('Days')
            ax3.grid(True, alpha=0.3)

            for bar, value in zip(bars, retention_values):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(retention_values) * 0.05,
                        f'{value:.1f}', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'privacy_metrics_comparison.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def _plot_overview_comparison(self) -> str:
        """Plot overview comparison of key metrics"""
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
        fig.suptitle('Overview: Framework Comparison Summary', fontsize=16, fontweight='bold')

        # F1-Score comparison
        security_data = self.results_data.get('security_accuracy', {})
        if security_data:
            baseline_f1 = security_data.get('baseline', {}).get('f1_score', 0)
            proposed_f1 = security_data.get('proposed', {}).get('f1_score', 0)

            bars1 = ax1.bar(['Baseline', 'Proposed'], [baseline_f1, proposed_f1],
                           color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax1.set_title('Security: F1-Score')
            ax1.set_ylabel('F1-Score')
            ax1.set_ylim(0, 1)
            ax1.grid(True, alpha=0.3)

            for bar, value in zip(bars1, [baseline_f1, proposed_f1]):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                        f'{value:.3f}', ha='center', va='bottom', fontweight='bold')

        # Average Latency comparison
        perf_data = self.results_data.get('performance_metrics', {})
        if perf_data:
            baseline_latency = perf_data.get('baseline', {}).get('avg_latency_ms', 0)
            proposed_latency = perf_data.get('proposed', {}).get('avg_latency_ms', 0)

            bars2 = ax2.bar(['Baseline', 'Proposed'], [baseline_latency, proposed_latency],
                           color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax2.set_title('Performance: Avg Latency')
            ax2.set_ylabel('Latency (ms)')
            ax2.grid(True, alpha=0.3)

            for bar, value in zip(bars2, [baseline_latency, proposed_latency]):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(baseline_latency, proposed_latency) * 0.02,
                        f'{value:.1f}', ha='center', va='bottom', fontweight='bold')

        # Step-up Challenge Rate comparison
        usability_data = self.results_data.get('usability_indicators', {})
        if usability_data:
            baseline_stepup = usability_data.get('baseline', {}).get('step_up_challenge_rate_pct', 0)
            proposed_stepup = usability_data.get('proposed', {}).get('step_up_challenge_rate_pct', 0)

            bars3 = ax3.bar(['Baseline', 'Proposed'], [baseline_stepup, proposed_stepup],
                           color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax3.set_title('Usability: Step-up Challenge Rate')
            ax3.set_ylabel('Percentage (%)')
            ax3.grid(True, alpha=0.3)

            for bar, value in zip(bars3, [baseline_stepup, proposed_stepup]):
                ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(baseline_stepup, proposed_stepup) * 0.02,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

        # Privacy Compliance comparison
        privacy_data = self.results_data.get('privacy_metrics', {})
        if privacy_data:
            baseline_compliance = privacy_data.get('baseline', {}).get('data_minimization_compliance_pct', 0)
            proposed_compliance = privacy_data.get('proposed', {}).get('data_minimization_compliance_pct', 0)

            bars4 = ax4.bar(['Baseline', 'Proposed'], [baseline_compliance, proposed_compliance],
                           color=['#FF6B6B', '#4ECDC4'], alpha=0.7)
            ax4.set_title('Privacy: Data Minimization Compliance')
            ax4.set_ylabel('Percentage (%)')
            ax4.set_ylim(0, 100)
            ax4.grid(True, alpha=0.3)

            for bar, value in zip(bars4, [baseline_compliance, proposed_compliance]):
                ax4.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                        f'{value:.1f}%', ha='center', va='bottom', fontweight='bold')

        plt.tight_layout()
        filename = os.path.join(self.output_dir, 'overview_comparison.png')
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        plt.close()

        return filename

    def generate_summary_tables(self) -> Dict[str, str]:
        """Generate summary tables for thesis results"""
        logger.info("Generating summary tables")

        tables = {}

        # Security Accuracy Summary Table
        if 'security_accuracy' in self.results_data:
            tables['security_accuracy'] = self._create_security_accuracy_table()

        # Performance Comparison Table
        if 'performance_metrics' in self.results_data:
            tables['performance'] = self._create_performance_table()

        # Usability Indicators Table
        if 'usability_indicators' in self.results_data:
            tables['usability'] = self._create_usability_table()

        # Privacy Metrics Table
        if 'privacy_metrics' in self.results_data:
            tables['privacy'] = self._create_privacy_table()

        # Basic Statistics Table
        basic_stats = self.calculate_basic_statistics()
        if basic_stats:
            tables['basic_statistics'] = self._create_basic_statistics_table(basic_stats)

        return tables

    def _create_security_accuracy_table(self) -> str:
        """Create security accuracy comparison table"""
        data = self.results_data.get('security_accuracy', {})

        table_data = []
        metrics = ['tpr', 'fpr', 'precision', 'recall', 'f1_score', 'accuracy']
        metric_names = ['TPR', 'FPR', 'Precision', 'Recall', 'F1-Score', 'Accuracy']

        for metric, name in zip(metrics, metric_names):
            baseline_val = data.get('baseline', {}).get(metric, 0)
            proposed_val = data.get('proposed', {}).get(metric, 0)
            improvement = ((proposed_val - baseline_val) / baseline_val * 100) if baseline_val > 0 else 0

            table_data.append({
                'Metric': name,
                'Baseline': f"{baseline_val:.3f}",
                'Proposed': f"{proposed_val:.3f}",
                'Improvement (%)': f"{improvement:+.1f}"
            })

        df = pd.DataFrame(table_data)
        filename = os.path.join(self.output_dir, 'security_accuracy_table.csv')
        df.to_csv(filename, index=False)

        return filename

    def _create_performance_table(self) -> str:
        """Create performance comparison table"""
        data = self.results_data.get('performance_metrics', {})

        table_data = []
        metrics = [
            ('avg_latency_ms', 'Avg. Decision Latency (ms)'),
            ('p95_latency_ms', '95th Percentile Latency (ms)'),
            ('throughput_rps', 'Throughput (req/s)'),
            ('cpu_utilization_pct', 'CPU Utilization (%)'),
            ('memory_utilization_mb', 'Memory Utilization (MB)'),
            ('success_rate', 'Success Rate')
        ]

        for metric_key, metric_name in metrics:
            baseline_val = data.get('baseline', {}).get(metric_key, 0)
            proposed_val = data.get('proposed', {}).get(metric_key, 0)

            if metric_key in ['avg_latency_ms', 'p95_latency_ms', 'cpu_utilization_pct', 'memory_utilization_mb']:
                # For these metrics, lower is better
                improvement = ((baseline_val - proposed_val) / baseline_val * 100) if baseline_val > 0 else 0
                overhead = f"{-improvement:+.1f}%"
            else:
                # For throughput and success rate, higher is better
                improvement = ((proposed_val - baseline_val) / baseline_val * 100) if baseline_val > 0 else 0
                overhead = f"{improvement:+.1f}%"

            if metric_key == 'success_rate':
                baseline_str = f"{baseline_val:.3f}"
                proposed_str = f"{proposed_val:.3f}"
            elif 'ms' in metric_name or 'MB' in metric_name:
                baseline_str = f"{baseline_val:.1f}"
                proposed_str = f"{proposed_val:.1f}"
            else:
                baseline_str = f"{baseline_val:.2f}"
                proposed_str = f"{proposed_val:.2f}"

            table_data.append({
                'Metric': metric_name,
                'Baseline MFA (No Validation)': baseline_str,
                'Proposed Framework (Validation + SIEM)': proposed_str,
                'Overhead': overhead
            })

        df = pd.DataFrame(table_data)
        filename = os.path.join(self.output_dir, 'performance_comparison_table.csv')
        df.to_csv(filename, index=False)

        return filename

    def _create_usability_table(self) -> str:
        """Create usability indicators table"""
        data = self.results_data.get('usability_indicators', {})

        table_data = []
        metrics = [
            ('step_up_challenge_rate_pct', 'Step-up Challenge Rate (%)'),
            ('user_friction_index', 'User Friction Index'),
            ('session_continuity_pct', 'Session Continuity (% sessions without disruption)'),
            ('avg_session_duration_min', 'Avg Session Duration (min)')
        ]

        for metric_key, metric_name in metrics:
            baseline_val = data.get('baseline', {}).get(metric_key, 0)
            proposed_val = data.get('proposed', {}).get(metric_key, 0)

            table_data.append({
                'Metric': metric_name,
                'Baseline': f"{baseline_val:.1f}",
                'Proposed': f"{proposed_val:.1f}"
            })

        df = pd.DataFrame(table_data)
        filename = os.path.join(self.output_dir, 'usability_indicators_table.csv')
        df.to_csv(filename, index=False)

        return filename

    def _create_privacy_table(self) -> str:
        """Create privacy metrics table"""
        data = self.results_data.get('privacy_metrics', {})

        table_data = []
        metrics = [
            ('data_minimization_compliance_pct', 'Data Minimization Compliance (%)'),
            ('avg_signal_retention_days', 'Avg. Signal Retention Duration (days)'),
            ('privacy_leakage_rate_pct', 'Privacy Leakage Rate (% reconstructed identifiers)')
        ]

        for metric_key, metric_name in metrics:
            baseline_val = data.get('baseline', {}).get(metric_key, 0)
            proposed_val = data.get('proposed', {}).get(metric_key, 0)

            table_data.append({
                'Metric': metric_name,
                'Baseline': f"{baseline_val:.1f}",
                'Proposed': f"{proposed_val:.1f}"
            })

        df = pd.DataFrame(table_data)
        filename = os.path.join(self.output_dir, 'privacy_preserving_metrics_table.csv')
        df.to_csv(filename, index=False)

        return filename

    def _create_basic_statistics_table(self, basic_stats: Dict[str, Dict[str, Any]]) -> str:
        """Create basic statistics comparison table"""
        table_data = []

        for metric_name, results in basic_stats.items():
            table_data.append({
                'Metric': metric_name.replace('_', ' ').title(),
                'Baseline Mean': f"{results.get('baseline_mean', 0):.3f}",
                'Proposed Mean': f"{results.get('proposed_mean', 0):.3f}",
                'Effect Size': f"{results.get('effect_size', 0):.3f}",
                'Improvement (%)': f"{results.get('improvement_pct', 0):+.1f}%",
                'Baseline N': str(results.get('sample_sizes', {}).get('baseline', 0)),
                'Proposed N': str(results.get('sample_sizes', {}).get('proposed', 0))
            })

        df = pd.DataFrame(table_data)
        filename = os.path.join(self.output_dir, 'basic_statistics_table.csv')
        df.to_csv(filename, index=False)

        return filename

    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive analysis report"""
        logger.info("Generating comprehensive analysis report")

        report_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_period': self.results_data.get('analysis_period_hours', 0),
            'summary': {},
            'detailed_results': self.results_data,
            'basic_statistics': self.calculate_basic_statistics()
        }

        # Generate summary statistics
        if 'comprehensive' in self.results_data:
            comprehensive = self.results_data['comprehensive']

            # Security summary
            security_data = comprehensive.get('security_accuracy', {})
            if security_data:
                baseline_f1 = security_data.get('baseline', {}).get('f1_score', 0)
                proposed_f1 = security_data.get('proposed', {}).get('f1_score', 0)
                report_data['summary']['security_improvement'] = {
                    'baseline_f1_score': baseline_f1,
                    'proposed_f1_score': proposed_f1,
                    'improvement_pct': ((proposed_f1 - baseline_f1) / baseline_f1 * 100) if baseline_f1 > 0 else 0
                }

            # Performance summary
            performance_data = comprehensive.get('performance_comparison', {})
            if performance_data:
                baseline_latency = performance_data.get('baseline', {}).get('avg_decision_latency_ms', 0)
                proposed_latency = performance_data.get('proposed', {}).get('avg_decision_latency_ms', 0)
                report_data['summary']['performance_impact'] = {
                    'baseline_latency_ms': baseline_latency,
                    'proposed_latency_ms': proposed_latency,
                    'latency_overhead_pct': ((proposed_latency - baseline_latency) / baseline_latency * 100) if baseline_latency > 0 else 0
                }

            # Overhead analysis
            overhead_data = comprehensive.get('overhead_analysis', {})
            if overhead_data:
                report_data['summary']['overhead'] = overhead_data

        # Save comprehensive report
        filename = os.path.join(self.output_dir, 'comprehensive_analysis_report.json')
        with open(filename, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        return filename

    def run_complete_analysis(self, hours: int = 168) -> Dict[str, Any]:
        """Run complete thesis analysis"""
        logger.info(f"Starting complete thesis analysis for {hours} hours")

        # Connect to database
        try:
            self.connect_database()
        except Exception as e:
            logger.warning(f"Database connection failed, continuing with API data only: {e}")

        # Collect comprehensive data
        logger.info("Collecting data...")
        self.collect_comprehensive_data(hours)

        # Generate visualizations
        logger.info("Generating visualizations...")
        visualizations = self.generate_visualizations()

        # Generate summary tables
        logger.info("Generating summary tables...")
        tables = self.generate_summary_tables()

        # Generate reports
        logger.info("Generating reports...")
        comprehensive_report = self.generate_comprehensive_report()

        # Calculate basic statistics
        basic_statistics = self.calculate_basic_statistics()

        results = {
            'analysis_completed': True,
            'output_directory': self.output_dir,
            'visualizations': visualizations,
            'tables': tables,
            'reports': {
                'comprehensive': comprehensive_report
            },
            'basic_statistics': basic_statistics,
            'summary_statistics': self.results_data.get('summary', {})
        }

        # Save analysis metadata
        metadata_file = os.path.join(self.output_dir, 'analysis_metadata.json')
        with open(metadata_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"Analysis complete! Results saved to: {self.output_dir}")
        return results


def load_config() -> Dict[str, str]:
    """Load configuration from environment variables"""
    return {
        'DB_DSN': os.getenv('DB_DSN', 'postgresql://postgres:password@localhost:5432/zta_framework'),
        'METRICS_URL': os.getenv('METRICS_URL', 'http://localhost:8030'),
        'OUTPUT_DIR': os.getenv('OUTPUT_DIR', './thesis-results'),
        'ES_HOST': os.getenv('ES_HOST', 'http://localhost:9200'),
        'ES_USER': os.getenv('ES_USER', 'elastic'),
        'ES_PASS': os.getenv('ES_PASS', 'changeme')
    }


def main():
    """Main entry point for thesis analysis"""
    parser = argparse.ArgumentParser(description='Simplified Thesis Results Analysis and Reporting')
    parser.add_argument('--hours', type=int, default=168,
                       help='Hours of data to analyze (default: 168 = 7 days)')
    parser.add_argument('--output-dir', type=str, default='./thesis-results',
                       help='Output directory for results')
    parser.add_argument('--config-file', type=str,
                       help='Configuration file (JSON format)')
    parser.add_argument('--metrics-only', action='store_true',
                       help='Only collect metrics without generating visualizations')
    parser.add_argument('--viz-only', action='store_true',
                       help='Only generate visualizations from existing data')

    args = parser.parse_args()

    # Load configuration
    config = load_config()
    if args.output_dir:
        config['OUTPUT_DIR'] = args.output_dir

    if args.config_file and os.path.exists(args.config_file):
        with open(args.config_file) as f:
            file_config = json.load(f)
            config.update(file_config)

    logger.info("Starting Multi-Source MFA ZTA Framework Thesis Analysis (Simplified)")
    logger.info(f"Analysis period: {args.hours} hours")
    logger.info(f"Output directory: {config['OUTPUT_DIR']}")

    try:
        analyzer = SimpleThesisAnalyzer(config)

        if args.viz_only:
            # Load existing data and generate visualizations only
            data_file = os.path.join(config['OUTPUT_DIR'], 'comprehensive_analysis_report.json')
            if os.path.exists(data_file):
                with open(data_file) as f:
                    analyzer.results_data = json.load(f).get('detailed_results', {})
                visualizations = analyzer.generate_visualizations()
                logger.info(f"Visualizations generated: {visualizations}")
            else:
                logger.error("No existing data found for visualization-only mode")
                sys.exit(1)

        elif args.metrics_only:
            # Collect metrics only
            try:
                analyzer.connect_database()
            except:
                logger.warning("Database connection failed, using API data only")
            data = analyzer.collect_comprehensive_data(args.hours)
            logger.info("Metrics collection completed")
            print(json.dumps(data, indent=2, default=str))

        else:
            # Run complete analysis
            results = analyzer.run_complete_analysis(args.hours)

            print("\n" + "="*60)
            print("THESIS ANALYSIS RESULTS SUMMARY (SIMPLIFIED)")
            print("="*60)

            if 'summary_statistics' in results:
                summary = results.get('summary_statistics', {})
                print(f"\nAnalysis Period: {args.hours} hours")
                print(f"Output Directory: {results['output_directory']}")

            print(f"\nGenerated Files:")
            if results.get('visualizations'):
                print("  Visualizations:")
                for name, path in results['visualizations'].items():
                    print(f"    - {name}: {os.path.basename(path)}")

            if results.get('tables'):
                print("  Data Tables:")
                for name, path in results['tables'].items():
                    print(f"    - {name}: {os.path.basename(path)}")

            if results.get('reports'):
                print("  Reports:")
                for name, path in results['reports'].items():
                    print(f"    - {name}: {os.path.basename(path)}")

            # Print key findings
            if results.get('basic_statistics'):
                print(f"\nBasic Statistical Comparisons:")
                for metric, stats in results['basic_statistics'].items():
                    improvement = stats.get('improvement_pct', 0)
                    effect_size = stats.get('effect_size', 0)
                    print(f"  • {metric.replace('_', ' ').title()}: {improvement:+.1f}% (effect size: {effect_size:.3f})")

            print(f"\n{'='*60}")
            print("Analysis completed successfully!")
            print(f"Results available in: {results['output_directory']}")
            print("="*60)

    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
