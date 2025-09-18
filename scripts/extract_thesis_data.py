#!/usr/bin/env python3
"""
Thesis Data Extraction Script
Extracts real metrics, tables, and data from the running Multi-Source MFA ZTA Framework
to replace placeholder content in thesis document.

Usage:
    python extract_thesis_data.py --output thesis_data/ --format json
    python extract_thesis_data.py --dashboard-export --kibana-url http://localhost:5601
    python extract_thesis_data.py --comparison-report --hours 168  # 7 days of data
"""

import os
import sys
import json
import csv
import asyncio
import argparse
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import httpx
import matplotlib.pyplot as plt
import seaborn as sns
from sqlalchemy import create_engine, text
from pathlib import Path

# Configuration
DEFAULT_SERVICES = {
    'metrics': 'http://localhost:8030',
    'baseline': 'http://localhost:8020',
    'gateway': 'http://localhost:8003',
    'validation': 'http://localhost:8001',
    'kibana': 'http://localhost:5601'
}

class ThesisDataExtractor:
    """Extracts data from running ZTA framework for thesis documentation"""

    def __init__(self, db_dsn: Optional[str] = None, services: Optional[Dict[str, str]] = None):
        self.db_dsn = db_dsn or os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres")
        self.services = services or DEFAULT_SERVICES
        self.engine = None
        self.setup_database()

    def setup_database(self):
        """Initialize database connection"""
        try:
            # Handle different DSN formats
            dsn = self.db_dsn
            if dsn.startswith("postgresql://"):
                dsn = "postgresql+psycopg://" + dsn[len("postgresql://"):]
            elif dsn.startswith("postgres://"):
                dsn = "postgresql+psycopg://" + dsn[len("postgres://"):]
            elif dsn.startswith("postgresql+psycopg://"):
                # Already in correct format
                pass

            # Ensure SSL mode is set for remote connections
            if "localhost" not in dsn and "127.0.0.1" not in dsn and "sslmode=" not in dsn:
                dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

            self.engine = create_engine(dsn, pool_pre_ping=True, future=True)
            with self.engine.connect() as c:
                c.execute(text("SELECT 1"))
            print(f"✓ Database connection established to: {dsn.split('@')[1].split('/')[0] if '@' in dsn else 'localhost'}")
        except Exception as e:
            print(f"✗ Database connection failed: {e}")
            print(f"  DSN format: {self.db_dsn[:50]}...")
            self.engine = None

    async def extract_framework_comparison_metrics(self, hours: int = 24) -> Dict[str, Any]:
        """Extract comprehensive framework comparison data"""
        print(f"📊 Extracting framework comparison metrics ({hours}h)...")

        data = {
            'extraction_time': datetime.utcnow().isoformat(),
            'time_period_hours': hours,
            'proposed_framework': {},
            'baseline_framework': {},
            'comparison_summary': {}
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Get metrics from metrics service
                metrics_response = await client.get(
                    f"{self.services['metrics']}/metrics/comparison",
                    params={"hours": hours}
                )
                if metrics_response.status_code == 200:
                    data['comparison_summary'] = metrics_response.json()

                # Get baseline specific stats
                baseline_response = await client.get(
                    f"{self.services['baseline']}/stats",
                    params={"hours": hours}
                )
                if baseline_response.status_code == 200:
                    data['baseline_framework'] = baseline_response.json()

        except Exception as e:
            print(f"⚠️  API extraction error: {e}")

        # Extract from database directly
        if self.engine:
            try:
                with self.engine.connect() as conn:
                    # Framework comparison summary
                    comparison_query = f"""
                        SELECT
                            framework_type,
                            COUNT(*) as total_events,
                            COUNT(*) FILTER (WHERE decision = 'allow') as allow_count,
                            COUNT(*) FILTER (WHERE decision = 'step_up') as stepup_count,
                            COUNT(*) FILTER (WHERE decision = 'deny') as deny_count,
                            AVG(risk_score) as avg_risk_score,
                            AVG(processing_time_ms) as avg_processing_time,
                            STDDEV(risk_score) as risk_score_stddev
                        FROM zta.framework_comparison
                        WHERE created_at > NOW() - INTERVAL '{hours} hours'
                        GROUP BY framework_type
                    """

                    comparison_results = conn.execute(text(comparison_query)).mappings().all()

                    for result in comparison_results:
                        framework = result['framework_type']
                        data[f"{framework}_framework"]['database_metrics'] = {
                            'total_events': result['total_events'],
                            'decision_distribution': {
                                'allow': result['allow_count'],
                                'step_up': result['stepup_count'],
                                'deny': result['deny_count']
                            },
                            'performance': {
                                'avg_risk_score': float(result['avg_risk_score'] if result['avg_risk_score'] is not None else 0),
                                'avg_processing_time_ms': float(result['avg_processing_time'] if result['avg_processing_time'] is not None else 0),
                                'risk_score_stddev': float(result['risk_score_stddev'] if result['risk_score_stddev'] is not None else 0)
                            }
                        }

                    # Security effectiveness metrics
                    security_query = f"""
                        SELECT
                            framework_type,
                            original_label,
                            COUNT(*) as total_events,
                            COUNT(*) FILTER (WHERE jsonb_array_length(predicted_threats) > 0) as threat_detected,
                            AVG(classification_accuracy) as avg_accuracy,
                            COUNT(*) FILTER (WHERE false_positive = true) as false_positives,
                            COUNT(*) FILTER (WHERE false_negative = true) as false_negatives
                        FROM zta.security_classifications
                        WHERE created_at > NOW() - INTERVAL '{hours} hours'
                        GROUP BY framework_type, original_label
                        ORDER BY framework_type, original_label
                    """

                    security_results = conn.execute(text(security_query)).mappings().all()

                    for result in security_results:
                        framework = result['framework_type']
                        if 'security_metrics' not in data[f"{framework}_framework"]:
                            data[f"{framework}_framework"]['security_metrics'] = []

                        data[f"{framework}_framework"]['security_metrics'].append({
                            'attack_type': result['original_label'],
                            'total_events': result['total_events'],
                            'detected': result['threat_detected'],
                            'detection_rate': (result['threat_detected'] / max(result['total_events'], 1)) * 100,
                            'avg_accuracy': float(result['avg_accuracy'] if result['avg_accuracy'] is not None else 0),
                            'false_positives': result['false_positives'],
                            'false_negatives': result['false_negatives']
                        })

            except Exception as e:
                print(f"⚠️  Database extraction error: {e}")

        return data

    def extract_performance_tables(self, hours: int = 24) -> Dict[str, Any]:
        """Extract performance comparison tables"""
        print(f"⚡ Extracting performance tables ({hours}h)...")

        if not self.engine:
            return {"error": "Database connection unavailable"}

        try:
            with self.engine.connect() as conn:
                # Service-level performance metrics
                service_perf_query = text("""
                    SELECT
                        service_name,
                        operation,
                        COUNT(*) as total_requests,
                        AVG(duration_ms) as avg_duration_ms,
                        MIN(duration_ms) as min_duration_ms,
                        MAX(duration_ms) as max_duration_ms,
                        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) as p95_duration_ms,
                        COUNT(*) FILTER (WHERE status = 'error') as error_count,
                        (COUNT(*) FILTER (WHERE status = 'error') * 100.0 / COUNT(*)) as error_rate
                    FROM zta.performance_metrics
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                    GROUP BY service_name, operation
                    ORDER BY service_name, operation
                """)

                service_results = conn.execute(service_perf_query, {"hours": hours}).mappings().all()

                # Framework processing time comparison
                framework_perf_query = text("""
                    SELECT
                        framework_type,
                        AVG(processing_time_ms) as avg_processing_time,
                        MIN(processing_time_ms) as min_processing_time,
                        MAX(processing_time_ms) as max_processing_time,
                        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY processing_time_ms) as median_processing_time,
                        PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY processing_time_ms) as p95_processing_time,
                        STDDEV(processing_time_ms) as processing_time_stddev
                    FROM zta.framework_comparison
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                    GROUP BY framework_type
                """)

                framework_results = conn.execute(framework_perf_query, {"hours": hours}).mappings().all()

                return {
                    'service_performance': [dict(r) for r in service_results],
                    'framework_performance': [dict(r) for r in framework_results],
                    'extraction_time': datetime.utcnow().isoformat()
                }

        except Exception as e:
            return {"error": str(e)}

    def extract_security_effectiveness_data(self, hours: int = 168) -> Dict[str, Any]:
        """Extract security effectiveness metrics for thesis evaluation"""
        print(f"🔒 Extracting security effectiveness data ({hours}h)...")

        if not self.engine:
            return {"error": "Database connection unavailable"}

        try:
            with self.engine.connect() as conn:
                # STRIDE threat detection effectiveness
                stride_query = text("""
                    SELECT
                        stride,
                        severity,
                        COUNT(*) as alert_count,
                        COUNT(DISTINCT session_id) as unique_sessions
                    FROM zta.siem_alerts
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                    GROUP BY stride, severity
                    ORDER BY stride, severity
                """)

                stride_results = conn.execute(stride_query, {"hours": hours}).mappings().all()

                # Attack detection accuracy by type
                attack_accuracy_query = text("""
                    WITH attack_stats AS (
                        SELECT
                            original_label,
                            framework_type,
                            COUNT(*) as total_samples,
                            SUM(CASE WHEN jsonb_array_length(predicted_threats) > 0 THEN 1 ELSE 0 END) as detected,
                            SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) as false_positives,
                            SUM(CASE WHEN false_negative THEN 1 ELSE 0 END) as false_negatives,
                            AVG(classification_accuracy) as avg_accuracy
                        FROM zta.security_classifications
                        WHERE created_at > NOW() - INTERVAL :hours HOUR
                        AND original_label IS NOT NULL
                        GROUP BY original_label, framework_type
                    )
                    SELECT
                        *,
                        (detected * 100.0 / NULLIF(total_samples, 0)) as detection_rate,
                        (false_positives * 100.0 / NULLIF(total_samples, 0)) as false_positive_rate,
                        (false_negatives * 100.0 / NULLIF(total_samples, 0)) as false_negative_rate
                    FROM attack_stats
                    ORDER BY framework_type, original_label
                """)

                accuracy_results = conn.execute(attack_accuracy_query, {"hours": hours}).mappings().all()

                # Multi-source correlation effectiveness
                correlation_query = text("""
                    SELECT
                        DATE(created_at) as date,
                        COUNT(*) as total_events,
                        COUNT(*) FILTER (WHERE factors::jsonb ? 'GPS_MISMATCH') as gps_anomalies,
                        COUNT(*) FILTER (WHERE factors::jsonb ? 'TLS_ANOMALY') as tls_anomalies,
                        COUNT(*) FILTER (WHERE factors::jsonb ? 'DEVICE_UNTRUSTED') as device_anomalies,
                        COUNT(*) FILTER (WHERE jsonb_array_length(factors::jsonb) > 1) as multi_factor_events
                    FROM zta.framework_comparison
                    WHERE created_at > NOW() - INTERVAL :hours HOUR
                    AND framework_type = 'proposed'
                    GROUP BY DATE(created_at)
                    ORDER BY date DESC
                """)

                correlation_results = conn.execute(correlation_query, {"hours": hours}).mappings().all()

                return {
                    'stride_detection': [dict(r) for r in stride_results],
                    'attack_accuracy': [dict(r) for r in accuracy_results],
                    'multi_source_correlation': [dict(r) for r in correlation_results],
                    'extraction_time': datetime.utcnow().isoformat()
                }

        except Exception as e:
            return {"error": str(e)}

    def generate_comparison_charts(self, data: Dict[str, Any], output_dir: Path):
        """Generate charts for thesis figures"""
        print("📈 Generating comparison charts...")

        charts_dir = output_dir / "charts"
        charts_dir.mkdir(exist_ok=True)

        plt.style.use('seaborn-v0_8')

        try:
            # Framework Decision Distribution
            if 'proposed_framework' in data and 'baseline_framework' in data:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

                # Decision distribution comparison
                frameworks = ['Proposed', 'Baseline']
                decisions = ['Allow', 'Step-up', 'Deny']

                proposed_metrics = data['proposed_framework'].get('database_metrics', {})
                baseline_metrics = data['baseline_framework'].get('database_metrics', {})

                if proposed_metrics and baseline_metrics:
                    proposed_dist = proposed_metrics.get('decision_distribution', {})
                    baseline_dist = baseline_metrics.get('decision_distribution', {})

                    proposed_values = [proposed_dist.get('allow', 0), proposed_dist.get('step_up', 0), proposed_dist.get('deny', 0)]
                    baseline_values = [baseline_dist.get('allow', 0), baseline_dist.get('step_up', 0), baseline_dist.get('deny', 0)]

                    x = range(len(decisions))
                    width = 0.35

                    ax1.bar([i - width/2 for i in x], proposed_values, width, label='Proposed', alpha=0.8)
                    ax1.bar([i + width/2 for i in x], baseline_values, width, label='Baseline', alpha=0.8)

                    ax1.set_xlabel('Decision Type')
                    ax1.set_ylabel('Number of Events')
                    ax1.set_title('Framework Decision Distribution')
                    ax1.set_xticks(x)
                    ax1.set_xticklabels(decisions)
                    ax1.legend()

                    # Processing time comparison
                    processing_times = [
                        proposed_metrics.get('performance', {}).get('avg_processing_time_ms', 0),
                        baseline_metrics.get('performance', {}).get('avg_processing_time_ms', 0)
                    ]

                    ax2.bar(frameworks, processing_times, alpha=0.8, color=['#1f77b4', '#ff7f0e'])
                    ax2.set_ylabel('Average Processing Time (ms)')
                    ax2.set_title('Framework Processing Time Comparison')

                plt.tight_layout()
                plt.savefig(charts_dir / 'framework_comparison.png', dpi=300, bbox_inches='tight')
                plt.close()

            # Security Effectiveness Chart
            if 'proposed_framework' in data and 'security_metrics' in data['proposed_framework']:
                security_data = data['proposed_framework']['security_metrics']
                if security_data:
                    fig, ax = plt.subplots(figsize=(10, 6))

                    attack_types = [item['attack_type'] for item in security_data]
                    detection_rates = [item['detection_rate'] for item in security_data]

                    bars = ax.bar(attack_types, detection_rates, alpha=0.8)
                    ax.set_ylabel('Detection Rate (%)')
                    ax.set_title('Attack Detection Effectiveness by Type')
                    ax.set_ylim(0, 100)

                    # Add value labels on bars
                    for bar, rate in zip(bars, detection_rates):
                        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                               f'{rate:.1f}%', ha='center', va='bottom')

                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    plt.savefig(charts_dir / 'security_effectiveness.png', dpi=300, bbox_inches='tight')
                    plt.close()

            print(f"✓ Charts saved to {charts_dir}")

        except Exception as e:
            print(f"⚠️  Chart generation error: {e}")

    def export_tables_for_latex(self, data: Dict[str, Any], output_dir: Path):
        """Export tables in LaTeX format for thesis"""
        print("📋 Exporting LaTeX tables...")

        tables_dir = output_dir / "latex_tables"
        tables_dir.mkdir(exist_ok=True)

        try:
            # Framework Comparison Table
            comparison_latex = """
\\begin{table}[htbp]
\\centering
\\caption{Framework Performance Comparison}
\\label{tab:framework_comparison}
\\begin{tabular}{|l|c|c|}
\\hline
\\textbf{Metric} & \\textbf{Proposed Framework} & \\textbf{Baseline Framework} \\\\
\\hline
"""

            if 'proposed_framework' in data and 'baseline_framework' in data:
                proposed = data['proposed_framework'].get('database_metrics', {})
                baseline = data['baseline_framework'].get('database_metrics', {})

                if proposed and baseline:
                    # Total Events
                    comparison_latex += f"Total Events & {proposed.get('total_events', 0)} & {baseline.get('total_events', 0)} \\\\\n"
                    comparison_latex += "\\hline\n"

                    # Decision Distribution
                    prop_dist = proposed.get('decision_distribution', {})
                    base_dist = baseline.get('decision_distribution', {})

                    comparison_latex += f"Allow Decisions & {prop_dist.get('allow', 0)} & {base_dist.get('allow', 0)} \\\\\n"
                    comparison_latex += f"Step-up (MFA) & {prop_dist.get('step_up', 0)} & {base_dist.get('step_up', 0)} \\\\\n"
                    comparison_latex += f"Deny Decisions & {prop_dist.get('deny', 0)} & {base_dist.get('deny', 0)} \\\\\n"
                    comparison_latex += "\\hline\n"

                    # Performance Metrics
                    prop_perf = proposed.get('performance', {})
                    base_perf = baseline.get('performance', {})

                    comparison_latex += f"Avg Risk Score & {prop_perf.get('avg_risk_score', 0):.3f} & {base_perf.get('avg_risk_score', 0):.3f} \\\\\n"
                    comparison_latex += f"Avg Processing Time (ms) & {prop_perf.get('avg_processing_time_ms', 0):.2f} & {base_perf.get('avg_processing_time_ms', 0):.2f} \\\\\n"

            comparison_latex += """\\hline
\\end{tabular}
\\end{table}
"""

            with open(tables_dir / "framework_comparison.tex", "w") as f:
                f.write(comparison_latex)

            # Security Effectiveness Table
            if 'proposed_framework' in data and 'security_metrics' in data['proposed_framework']:
                security_data = data['proposed_framework']['security_metrics']

                security_latex = """
\\begin{table}[htbp]
\\centering
\\caption{Security Detection Effectiveness by Attack Type}
\\label{tab:security_effectiveness}
\\begin{tabular}{|l|c|c|c|c|}
\\hline
\\textbf{Attack Type} & \\textbf{Total Events} & \\textbf{Detected} & \\textbf{Detection Rate} & \\textbf{Accuracy} \\\\
\\hline
"""

                for item in security_data:
                    security_latex += f"{item['attack_type']} & {item['total_events']} & {item['detected']} & {item['detection_rate']:.1f}\\% & {item['avg_accuracy']:.3f} \\\\\n"

                security_latex += """\\hline
\\end{tabular}
\\end{table}
"""

                with open(tables_dir / "security_effectiveness.tex", "w") as f:
                    f.write(security_latex)

            print(f"✓ LaTeX tables saved to {tables_dir}")

        except Exception as e:
            print(f"⚠️  LaTeX export error: {e}")

    async def extract_kibana_dashboards(self, kibana_url: str, output_dir: Path):
        """Extract dashboard configurations and sample visualizations"""
        print(f"📊 Extracting Kibana dashboards from {kibana_url}...")

        dashboards_dir = output_dir / "kibana_dashboards"
        dashboards_dir.mkdir(exist_ok=True)

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                # Try to get dashboard list
                try:
                    response = await client.get(f"{kibana_url}/api/saved_objects/_find?type=dashboard")
                    if response.status_code == 200:
                        dashboards = response.json()
                        with open(dashboards_dir / "dashboards_list.json", "w") as f:
                            json.dump(dashboards, f, indent=2)
                        print(f"✓ Found {len(dashboards.get('saved_objects', []))} dashboards")
                except Exception as e:
                    print(f"⚠️  Could not access Kibana API: {e}")

                # Generate sample dashboard configuration
                sample_dashboard = {
                    "version": "8.0.0",
                    "objects": [
                        {
                            "id": "mfa-events-dashboard",
                            "type": "dashboard",
                            "attributes": {
                                "title": "Multi-Source MFA ZTA Framework Dashboard",
                                "description": "Real-time monitoring of authentication decisions and security events",
                                "panelsJSON": json.dumps([
                                    {
                                        "gridData": {"x": 0, "y": 0, "w": 24, "h": 12},
                                        "panelIndex": "1",
                                        "embeddableConfig": {},
                                        "panelRefName": "panel_1"
                                    }
                                ]),
                                "kibanaSavedObjectMeta": {
                                    "searchSourceJSON": json.dumps({
                                        "query": {"match_all": {}},
                                        "filter": []
                                    })
                                }
                            }
                        }
                    ]
                }

                with open(dashboards_dir / "sample_dashboard_config.json", "w") as f:
                    json.dump(sample_dashboard, f, indent=2)

                print(f"✓ Dashboard configurations saved to {dashboards_dir}")

        except Exception as e:
            print(f"⚠️  Dashboard extraction error: {e}")

    async def generate_comprehensive_report(self, hours: int = 24, output_dir: Optional[Path] = None):
        """Generate comprehensive thesis data report"""
        if output_dir is None:
            output_dir = Path("thesis_data") / datetime.now().strftime("%Y%m%d_%H%M%S")

        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"🎓 Generating comprehensive thesis data report...")
        print(f"📁 Output directory: {output_dir}")

        # Extract all data
        framework_data = await self.extract_framework_comparison_metrics(hours)
        performance_data = self.extract_performance_tables(hours)
        security_data = self.extract_security_effectiveness_data(hours)

        # Combine all data
        comprehensive_data = {
            'metadata': {
                'extraction_timestamp': datetime.utcnow().isoformat(),
                'time_period_hours': hours,
                'system_info': {
                    'database_connected': self.engine is not None,
                    'services_configured': list(self.services.keys())
                }
            },
            'framework_comparison': framework_data,
            'performance_metrics': performance_data,
            'security_effectiveness': security_data
        }

        # Save master data file
        with open(output_dir / "comprehensive_thesis_data.json", "w") as f:
            json.dump(comprehensive_data, f, indent=2)

        # Generate individual CSV files
        csv_dir = output_dir / "csv_data"
        csv_dir.mkdir(exist_ok=True)

        # Framework comparison CSV
        if isinstance(performance_data, dict) and 'framework_performance' in performance_data:
            df_framework = pd.DataFrame(performance_data['framework_performance'])
            df_framework.to_csv(csv_dir / "framework_performance.csv", index=False)

        # Security effectiveness CSV
        if isinstance(security_data, dict) and 'attack_accuracy' in security_data:
            df_security = pd.DataFrame(security_data['attack_accuracy'])
            df_security.to_csv(csv_dir / "security_effectiveness.csv", index=False)

        # Generate charts
        self.generate_comparison_charts(framework_data, output_dir)

        # Generate LaTeX tables
        self.export_tables_for_latex(framework_data, output_dir)

        # Extract dashboard configurations
        await self.extract_kibana_dashboards(self.services.get('kibana', ''), output_dir)

        # Generate summary report
        summary_file = output_dir / "THESIS_DATA_SUMMARY.md"
        with open(summary_file, "w") as f:
            f.write(f"""# Thesis Data Extraction Summary

Generated: {datetime.utcnow().isoformat()}
Time Period: {hours} hours
System Database: {'Connected' if self.engine else 'Not Connected'}

## Files Generated

### Data Files
- `comprehensive_thesis_data.json` - Master data file with all metrics
- `csv_data/` - Individual CSV files for analysis
- `charts/` - Generated charts and figures
- `latex_tables/` - LaTeX table code for thesis
- `kibana_dashboards/` - Dashboard configurations

### Key Metrics Available

#### Framework Comparison
- Decision distribution (Allow/Step-up/Deny)
- Processing time comparison
- Risk score analysis
- Accuracy measurements

#### Security Effectiveness
- Attack detection rates by type
- False positive/negative analysis
- STRIDE threat model coverage
- Multi-source correlation effectiveness

#### Performance Analysis
- Service-level performance metrics
- End-to-end processing times
- System reliability metrics
- Scalability measurements

## Usage Instructions

1. **For Thesis Tables**: Use LaTeX files in `latex_tables/` directory
2. **For Figures**: Use PNG files in `charts/` directory
3. **For Analysis**: Load `comprehensive_thesis_data.json` into analysis tools
4. **For Dashboards**: Import configurations from `kibana_dashboards/`

## Data Refresh

Run this extraction script regularly to get updated metrics:
```bash
python extract_thesis_data.py --hours 168 --output new_extraction/
```
""")

        print(f"✅ Comprehensive thesis data report generated!")
        print(f"📊 {len(os.listdir(output_dir))} files created in {output_dir}")

        return comprehensive_data

async def main():
    parser = argparse.ArgumentParser(description="Extract thesis data from Multi-Source MFA ZTA Framework")
    parser.add_argument("--hours", type=int, default=24, help="Hours of data to analyze (default: 24 hours)")
    parser.add_argument("--output", type=str, help="Output directory path")
    parser.add_argument("--format", choices=["json", "csv", "both"], default="both", help="Output format")
    parser.add_argument("--comparison-only", action="store_true", help="Extract only framework comparison data")
    parser.add_argument("--dashboard-export", action="store_true", help="Export Kibana dashboard configurations")
    parser.add_argument("--kibana-url", type=str, default="http://localhost:5601", help="Kibana URL for dashboard export")
    parser.add_argument("--db-dsn", type=str, help="Database connection string (overrides env)")

    args = parser.parse_args()

    # Setup output directory
    if args.output:
        output_dir = Path(args.output)
    else:
        output_dir = Path("thesis_data") / datetime.now().strftime("%Y%m%d_%H%M%S")

    output_dir.mkdir(parents=True, exist_ok=True)

    # Initialize extractor
    extractor = ThesisDataExtractor(db_dsn=args.db_dsn)

    if args.comparison_only:
        print("🔄 Extracting framework comparison data only...")
        data = await extractor.extract_framework_comparison_metrics(args.hours)

        with open(output_dir / "framework_comparison.json", "w") as f:
            json.dump(data, f, indent=2)

        if args.format in ["csv", "both"]:
            # Convert to CSV format
            pass  # Implementation depends on data structure

        print(f"✅ Framework comparison data saved to {output_dir}")

    elif args.dashboard_export:
        print("📊 Extracting dashboard configurations...")
        await extractor.extract_kibana_dashboards(args.kibana_url, output_dir)
        print(f"✅ Dashboard configurations saved to {output_dir}")

    else:
        print("🎓 Generating comprehensive thesis report...")
        comprehensive_data = await extractor.generate_comprehensive_report(args.hours, output_dir)
        print(f"✅ All thesis data extracted successfully!")


if __name__ == "__main__":
    asyncio.run(main())
