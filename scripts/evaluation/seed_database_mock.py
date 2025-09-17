#!/usr/bin/env python3
"""
Mock Database Seeder for Demonstration
This creates a simulation of database seeding without requiring actual DB connection
"""
import os
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any

class MockDatabaseSeeder:
    """Mock seeder that simulates database operations for demo purposes"""

    def __init__(self, dsn=None):
        self.dsn = dsn or os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres")
        self.seeded_data = {}
        print(f"[MOCK_DB] Mock seeder initialized with DSN: {self._mask_dsn(self.dsn)}")

    def _mask_dsn(self, dsn: str) -> str:
        """Mask password in DSN for logging"""
        try:
            if '@' in dsn and '://' in dsn:
                protocol, rest = dsn.split('://', 1)
                if '@' in rest:
                    creds, host = rest.split('@', 1)
                    if ':' in creds:
                        user, _ = creds.split(':', 1)
                        return f"{protocol}://{user}:***@{host}"
            return dsn
        except:
            return dsn

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"mock-{int(time.time())}-{random.randint(1000, 9999)}"

    def _generate_baseline_decisions(self, num_records: int = 100) -> List[Dict[str, Any]]:
        """Generate mock baseline decision records"""
        decisions = []
        decision_types = ["allow", "step_up", "deny"]
        factor_options = [
            "SUSPICIOUS_IP", "OUTSIDE_HOURS", "UNKNOWN_DEVICE",
            "MULTIPLE_FAILURES", "DDOS", "WEB_ATTACK", "BOT",
            "LOCATION_ANOMALY", "TLS_VULNERABILITY"
        ]

        for i in range(num_records):
            decision_type = random.choices(
                decision_types,
                weights=[60, 30, 10]  # More allows, some step-ups, few denies
            )[0]

            # Risk score correlates with decision
            if decision_type == "allow":
                risk_score = random.uniform(0.0, 0.3)
                factors = random.sample(factor_options, random.randint(0, 2))
            elif decision_type == "step_up":
                risk_score = random.uniform(0.3, 0.7)
                factors = random.sample(factor_options, random.randint(1, 4))
            else:  # deny
                risk_score = random.uniform(0.7, 1.0)
                factors = random.sample(factor_options, random.randint(2, 6))

            decisions.append({
                "session_id": self._generate_session_id(),
                "decision": decision_type,
                "risk_score": round(risk_score, 3),
                "factors": factors,
                "device_fingerprint": f"device-{random.randint(1000, 9999)}",
                "original_signals": {
                    "ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "timestamp": (datetime.now() - timedelta(hours=random.randint(0, 48))).isoformat()
                },
                "created_at": datetime.now() - timedelta(minutes=random.randint(0, 2880))
            })

        return decisions

    def _generate_framework_comparison(self, num_records: int = 80) -> List[Dict[str, Any]]:
        """Generate mock framework comparison records"""
        comparisons = []
        comparison_ids = [f"comp-{i}" for i in range(1, 6)]  # 5 different comparison runs

        for i in range(num_records):
            comparison_id = random.choice(comparison_ids)
            framework = random.choice(["proposed", "baseline"])
            session_id = self._generate_session_id()

            # Proposed framework generally performs better
            if framework == "proposed":
                decision = random.choices(["allow", "step_up", "deny"], weights=[65, 25, 10])[0]
                processing_time = random.randint(20, 60)  # Faster processing
                if decision == "allow":
                    risk_score = random.uniform(0.0, 0.3)
                elif decision == "step_up":
                    risk_score = random.uniform(0.3, 0.7)
                else:
                    risk_score = random.uniform(0.7, 1.0)
            else:  # baseline
                decision = random.choices(["allow", "step_up", "deny"], weights=[60, 30, 10])[0]
                processing_time = random.randint(40, 120)  # Slower processing
                if decision == "allow":
                    risk_score = random.uniform(0.0, 0.4)
                elif decision == "step_up":
                    risk_score = random.uniform(0.3, 0.8)
                else:
                    risk_score = random.uniform(0.7, 1.0)

            enforcement_map = {
                "allow": "ALLOW",
                "step_up": "MFA_REQUIRED",
                "deny": "DENY"
            }

            factors = []
            if decision != "allow":
                factors = random.sample([
                    "SUSPICIOUS_IP", "OUTSIDE_HOURS", "UNKNOWN_DEVICE",
                    "DDOS", "WEB_ATTACK", "BOT", "INFILTRATION"
                ], random.randint(1, 4))

            comparisons.append({
                "comparison_id": comparison_id,
                "framework_type": framework,
                "session_id": session_id,
                "decision": decision,
                "risk_score": round(risk_score, 3),
                "enforcement": enforcement_map[decision],
                "factors": factors,
                "processing_time_ms": processing_time,
                "created_at": datetime.now() - timedelta(minutes=random.randint(0, 1440))
            })

        return comparisons

    def _generate_mfa_events(self, num_records: int = 100) -> List[Dict[str, Any]]:
        """Generate mock MFA events"""
        events = []
        outcomes = ["success", "failed", "sent"]

        for i in range(num_records):
            session_id = self._generate_session_id()
            outcome = random.choice(outcomes)

            risk_score = random.uniform(0.0, 1.0)
            decision = "allow" if risk_score < 0.3 else ("step_up" if risk_score < 0.7 else "deny")

            detail = {
                "risk": risk_score,
                "decision": decision,
                "enforcement": "ALLOW" if decision == "allow" else ("MFA_REQUIRED" if decision == "step_up" else "DENY"),
                "method": "sms" if outcome == "sent" else "password",
                "signals_used": ["ip_geo", "device_posture", "tls_fp", "gps"]
            }

            events.append({
                "session_id": session_id,
                "outcome": outcome,
                "detail": detail,
                "created_at": datetime.now() - timedelta(minutes=random.randint(0, 1440))
            })

        return events

    def seed_all_tables(self):
        """Mock seed all tables with test data"""
        print("[MOCK_SEED] Starting mock database seeding...")

        try:
            # Simulate seeding operations
            print("[MOCK_SEED] Clearing existing test data...")
            time.sleep(0.5)  # Simulate work
            print("[MOCK_SEED]   Cleared baseline_decisions")
            print("[MOCK_SEED]   Cleared framework_comparison")
            print("[MOCK_SEED]   Cleared mfa_events")

            # Generate and "store" data
            print("[MOCK_SEED] Generating baseline_decisions...")
            self.seeded_data["baseline_decisions"] = self._generate_baseline_decisions(100)
            time.sleep(0.3)

            print("[MOCK_SEED] Generating framework_comparison...")
            self.seeded_data["framework_comparison"] = self._generate_framework_comparison(80)
            time.sleep(0.3)

            print("[MOCK_SEED] Generating mfa_events...")
            self.seeded_data["mfa_events"] = self._generate_mfa_events(100)
            time.sleep(0.3)

            print("[MOCK_SEED] Mock database seeding completed successfully!")

            # Generate mock metrics file
            self._generate_mock_metrics_file()

            # Print summary
            print("\n[SUMMARY] Mock seeded data:")
            print(f"  - {len(self.seeded_data['baseline_decisions'])} baseline decisions")
            print(f"  - {len(self.seeded_data['framework_comparison'])} framework comparisons")
            print(f"  - {len(self.seeded_data['mfa_events'])} MFA events")
            print("  - Mock metrics file generated")

        except Exception as e:
            print(f"[MOCK_SEED] Mock seeding failed: {e}")
            raise

    def _generate_mock_metrics_file(self):
        """Generate a mock metrics file that simulates what would be returned from database"""

        # Calculate summary metrics from generated data
        baseline_decisions = self.seeded_data.get("baseline_decisions", [])
        mfa_events = self.seeded_data.get("mfa_events", [])
        comparisons = self.seeded_data.get("framework_comparison", [])

        # Generate realistic summary
        total_events = len(mfa_events)
        success_count = sum(1 for event in mfa_events if event["detail"]["decision"] == "allow")
        mfa_count = sum(1 for event in mfa_events if event["detail"]["decision"] == "step_up")

        success_rate = (success_count / max(total_events, 1)) * 100
        mfa_stepup_rate = (mfa_count / max(total_events, 1)) * 100

        # Threat detection from comparisons
        total_threats = sum(1 for comp in comparisons
                          if comp["decision"] in ["step_up", "deny"] and comp["factors"])
        detected_threats = sum(1 for comp in comparisons
                             if comp["factors"] and len(comp["factors"]) > 0)

        threat_detection_rate = (detected_threats / max(len(comparisons), 1)) * 100
        false_positive_rate = random.uniform(5.0, 15.0)  # Mock FP rate

        mock_metrics = {
            "summary": {
                "total_events": total_events,
                "success_rate": round(success_rate, 1),
                "mfa_stepup_rate": round(mfa_stepup_rate, 1),
                "threat_detection_rate": round(threat_detection_rate, 1),
                "false_positive_rate": round(false_positive_rate, 1)
            },
            "detailed_metrics": {
                "security": {
                    "authentication_outcomes": {
                        "success": success_count,
                        "failed": total_events - success_count - mfa_count,
                        "sent": mfa_count
                    },
                    "risk_distribution": {
                        "low": random.randint(40, 60),
                        "medium": random.randint(25, 35),
                        "high": random.randint(10, 20)
                    },
                    "enforcement_actions": [
                        {"enforcement": "ALLOW", "count": success_count, "avg_risk": 0.15},
                        {"enforcement": "MFA_REQUIRED", "count": mfa_count, "avg_risk": 0.52},
                        {"enforcement": "DENY", "count": random.randint(5, 15), "avg_risk": 0.85}
                    ]
                },
                "detection": {
                    "threat_detection_by_label": [
                        {"original_label": "DDOS", "detected_threats": 2, "count": 8},
                        {"original_label": "WEB_ATTACK", "detected_threats": 1, "count": 12},
                        {"original_label": "BOT", "detected_threats": 3, "count": 6},
                        {"original_label": "BENIGN", "detected_threats": 0, "count": 45}
                    ],
                    "quality_metrics": [
                        {"missing_signals": 0, "count": 65, "avg_threats_detected": 1.2},
                        {"missing_signals": 1, "count": 25, "avg_threats_detected": 0.8},
                        {"missing_signals": 2, "count": 10, "avg_threats_detected": 0.3}
                    ]
                },
                "decision": {
                    "decision_distribution": [
                        {"decision": "allow", "count": success_count, "avg_risk": 0.18, "min_risk": 0.0, "max_risk": 0.3},
                        {"decision": "step_up", "count": mfa_count, "avg_risk": 0.54, "min_risk": 0.3, "max_risk": 0.7},
                        {"decision": "deny", "count": random.randint(5, 15), "avg_risk": 0.83, "min_risk": 0.7, "max_risk": 1.0}
                    ]
                }
            },
            "_mock_note": "This is mock data generated for demonstration purposes"
        }

        # Save mock metrics file
        output_dir = "evaluation_results"
        os.makedirs(output_dir, exist_ok=True)

        mock_file = os.path.join(output_dir, "mock_metrics.json")
        with open(mock_file, 'w') as f:
            json.dump(mock_metrics, f, indent=2, default=str)

        print(f"[MOCK_SEED] Mock metrics saved to {mock_file}")

    def export_seeded_data(self, output_file: str = "mock_seeded_data.json"):
        """Export all seeded data to file for inspection"""
        with open(output_file, 'w') as f:
            json.dump(self.seeded_data, f, indent=2, default=str)
        print(f"[MOCK_SEED] Seeded data exported to {output_file}")


def main():
    """Main entry point for mock seeding"""
    import argparse

    parser = argparse.ArgumentParser(description="Mock Database Seeding Script")
    parser.add_argument("--db-dsn",
                       default=os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres"),
                       help="Database DSN (for display only in mock mode)")
    parser.add_argument("--export-data",
                       action="store_true",
                       help="Export generated data to JSON file")

    args = parser.parse_args()

    try:
        seeder = MockDatabaseSeeder(dsn=args.db_dsn)
        seeder.seed_all_tables()

        if args.export_data:
            seeder.export_seeded_data()

        print("\n[SUCCESS] Mock database seeded successfully!")
        print("\n[INFO] This is a mock demonstration. To use real database:")
        print("  1. Install PostgreSQL driver: pip install psycopg2-binary")
        print("  2. Set DB_DSN environment variable")
        print("  3. Run the actual seed_database.py script")
        print("  4. Or use: python3 run_evaluation.py --seed-database")

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Mock seeding interrupted by user")
    except Exception as e:
        print(f"\n[ERROR] Mock seeding failed: {e}")
        return 1

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
