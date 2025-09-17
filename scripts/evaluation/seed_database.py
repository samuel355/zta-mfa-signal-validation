#!/usr/bin/env python3
"""
Database Seeding Script
Seeds the database with initial test data for evaluation purposes
"""
import os
import sys
import json
import random
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from sqlalchemy import create_engine, text

# Database configuration
DB_DSN = os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres")

class DatabaseSeeder:
    """Seeds database with test data for framework comparison"""

    def __init__(self, dsn=None):
        self.engine = None
        self.dsn = dsn or os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres")
        self._init_database()

    def _init_database(self):
        """Initialize database connection"""
        try:
            # Try different psycopg versions
            dsn = self.dsn
            if self.dsn.startswith("postgresql://"):
                # Try psycopg first, fall back to psycopg2
                try:
                    dsn = "postgresql+psycopg://" + self.dsn[len("postgresql://"):]
                except:
                    dsn = "postgresql+psycopg2://" + self.dsn[len("postgresql://"):]
            elif self.dsn.startswith("postgres://"):
                try:
                    dsn = "postgresql+psycopg://" + self.dsn[len("postgres://"):]
                except:
                    dsn = "postgresql+psycopg2://" + self.dsn[len("postgres://"):]

            if "sslmode=" not in dsn:
                dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

            try:
                self.engine = create_engine(dsn, pool_pre_ping=True)
            except Exception as e:
                # Fall back to psycopg2 if psycopg fails
                if "psycopg" in dsn and "+psycopg://" in dsn:
                    dsn = dsn.replace("+psycopg://", "+psycopg2://")
                    self.engine = create_engine(dsn, pool_pre_ping=True)
                else:
                    raise e

            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            print("[DB] Connected successfully")
        except Exception as e:
            print(f"[DB] Connection failed: {e}")
            print("[DB] Make sure database is running and credentials are correct")
            print(f"[DB] DSN: {self.dsn}")
            sys.exit(1)

    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"seed-{int(time.time())}-{random.randint(1000, 9999)}"

    def _generate_baseline_decisions(self, num_records: int = 100) -> List[Dict[str, Any]]:
        """Generate baseline decision records"""
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

    def _generate_auth_attempts(self, num_records: int = 150) -> List[Dict[str, Any]]:
        """Generate authentication attempt records"""
        attempts = []
        outcomes = ["success", "failed", "mfa_required"]

        for i in range(num_records):
            outcome = random.choices(
                outcomes,
                weights=[70, 20, 10]  # Most successful, some failed, few MFA
            )[0]

            risk_score = random.uniform(0.0, 1.0) if outcome != "success" else random.uniform(0.0, 0.4)
            factors = []

            if outcome in ["failed", "mfa_required"]:
                factors = random.sample([
                    "INVALID_CREDENTIALS", "SUSPICIOUS_IP", "UNKNOWN_DEVICE",
                    "BRUTE_FORCE", "LOCATION_ANOMALY"
                ], random.randint(1, 3))

            attempts.append({
                "session_id": self._generate_session_id(),
                "outcome": outcome,
                "risk_score": round(risk_score, 3),
                "factors": factors,
                "created_at": datetime.now() - timedelta(minutes=random.randint(0, 2880))
            })

        return attempts

    def _generate_framework_comparison(self, num_records: int = 80) -> List[Dict[str, Any]]:
        """Generate framework comparison records"""
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

    def _generate_security_classifications(self, num_records: int = 120) -> List[Dict[str, Any]]:
        """Generate security classification records"""
        classifications = []

        # CICIDS attack types
        attack_labels = [
            "BENIGN", "DDoS", "PortScan", "Bot", "Infiltration",
            "Web Attack – Brute Force", "Web Attack – XSS",
            "Web Attack – Sql Injection", "Heartbleed"
        ]

        frameworks = ["proposed", "baseline"]

        for i in range(num_records):
            framework = random.choice(frameworks)
            original_label = random.choice(attack_labels)
            session_id = self._generate_session_id()

            # Determine if this is actually malicious
            is_malicious = original_label != "BENIGN"

            # Proposed framework has better detection rates
            if framework == "proposed":
                detection_accuracy = 0.92 if is_malicious else 0.95
            else:  # baseline
                detection_accuracy = 0.78 if is_malicious else 0.88

            # Determine if threats were detected correctly
            detected_correctly = random.random() < detection_accuracy

            if is_malicious and detected_correctly:
                # True positive - detected actual threat
                predicted_threats = [original_label.upper().replace(" ", "_")]
                false_positive = False
                false_negative = False
            elif is_malicious and not detected_correctly:
                # False negative - missed actual threat
                predicted_threats = []
                false_positive = False
                false_negative = True
            elif not is_malicious and detected_correctly:
                # True negative - correctly identified as benign
                predicted_threats = []
                false_positive = False
                false_negative = False
            else:
                # False positive - flagged benign as threat
                predicted_threats = [random.choice(["DDOS", "WEB_ATTACK", "BOT"])]
                false_positive = True
                false_negative = False

            accuracy_score = 1.0 if (is_malicious == bool(predicted_threats)) else 0.0

            classifications.append({
                "session_id": session_id,
                "original_label": original_label,
                "predicted_threats": predicted_threats,
                "framework_type": framework,
                "classification_accuracy": accuracy_score,
                "false_positive": false_positive,
                "false_negative": false_negative,
                "created_at": datetime.now() - timedelta(minutes=random.randint(0, 1440))
            })

        return classifications

    def _generate_performance_metrics(self, num_records: int = 200) -> List[Dict[str, Any]]:
        """Generate performance metrics records"""
        metrics = []

        services = [
            ("validation", "validate"), ("trust", "score"), ("gateway", "decision"),
            ("baseline", "decision"), ("siem", "alert"), ("metrics", "collect")
        ]

        for i in range(num_records):
            service_name, operation = random.choice(services)
            session_id = self._generate_session_id()

            # Different services have different performance characteristics
            if service_name == "validation":
                duration_ms = random.randint(10, 40)
            elif service_name == "trust":
                duration_ms = random.randint(15, 50)
            elif service_name == "gateway":
                duration_ms = random.randint(5, 25)
            elif service_name == "baseline":
                duration_ms = random.randint(30, 80)
            elif service_name == "siem":
                duration_ms = random.randint(20, 60)
            else:  # metrics
                duration_ms = random.randint(50, 200)

            start_time = datetime.now() - timedelta(minutes=random.randint(0, 1440))
            end_time = start_time + timedelta(milliseconds=duration_ms)

            status = "success" if random.random() > 0.05 else "error"  # 95% success rate

            metrics.append({
                "session_id": session_id,
                "service_name": service_name,
                "operation": operation,
                "start_time": start_time,
                "end_time": end_time,
                "status": status,
                "error_message": "Connection timeout" if status == "error" else None
            })

        return metrics

    def _generate_mfa_events(self, num_records: int = 100) -> List[Dict[str, Any]]:
        """Generate MFA events for the main tables"""
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
        """Seed all tables with test data"""
        print("[SEED] Starting database seeding...")

        try:
            with self.engine.begin() as conn:
                # Clear existing data
                print("[SEED] Clearing existing test data...")
                tables_to_clear = [
                    "zta.framework_comparison",
                    "zta.security_classifications",
                    "zta.performance_metrics",
                    "zta.baseline_decisions",
                    "zta.baseline_auth_attempts",
                    "zta.mfa_events"
                ]

                for table in tables_to_clear:
                    try:
                        conn.execute(text(f"DELETE FROM {table} WHERE session_id LIKE 'seed-%'"))
                        print(f"[SEED]   Cleared {table}")
                    except Exception as e:
                        print(f"[SEED]   Warning: Could not clear {table}: {e}")

                # Seed baseline decisions
                print("[SEED] Seeding baseline_decisions...")
                baseline_decisions = self._generate_baseline_decisions(100)
                for decision in baseline_decisions:
                    conn.execute(text("""
                        INSERT INTO zta.baseline_decisions
                        (session_id, decision, risk_score, factors, device_fingerprint,
                         original_signals, method, created_at)
                        VALUES (:session_id, :decision, :risk_score, :factors, :device_fingerprint,
                                :original_signals, 'baseline_mfa', :created_at)
                    """), {
                        "session_id": decision["session_id"],
                        "decision": decision["decision"],
                        "risk_score": decision["risk_score"],
                        "factors": json.dumps(decision["factors"]),
                        "device_fingerprint": decision["device_fingerprint"],
                        "original_signals": json.dumps(decision["original_signals"]),
                        "created_at": decision["created_at"]
                    })

                # Seed auth attempts
                print("[SEED] Seeding baseline_auth_attempts...")
                auth_attempts = self._generate_auth_attempts(150)
                for attempt in auth_attempts:
                    conn.execute(text("""
                        INSERT INTO zta.baseline_auth_attempts
                        (session_id, outcome, risk_score, factors, created_at)
                        VALUES (:session_id, :outcome, :risk_score, :factors, :created_at)
                    """), {
                        "session_id": attempt["session_id"],
                        "outcome": attempt["outcome"],
                        "risk_score": attempt["risk_score"],
                        "factors": json.dumps(attempt["factors"]),
                        "created_at": attempt["created_at"]
                    })

                # Seed framework comparison
                print("[SEED] Seeding framework_comparison...")
                comparisons = self._generate_framework_comparison(80)
                for comp in comparisons:
                    conn.execute(text("""
                        INSERT INTO zta.framework_comparison
                        (comparison_id, framework_type, session_id, decision, risk_score,
                         enforcement, factors, processing_time_ms, created_at)
                        VALUES (:comparison_id, :framework_type, :session_id, :decision, :risk_score,
                                :enforcement, :factors, :processing_time_ms, :created_at)
                    """), {
                        "comparison_id": comp["comparison_id"],
                        "framework_type": comp["framework_type"],
                        "session_id": comp["session_id"],
                        "decision": comp["decision"],
                        "risk_score": comp["risk_score"],
                        "enforcement": comp["enforcement"],
                        "factors": json.dumps(comp["factors"]),
                        "processing_time_ms": comp["processing_time_ms"],
                        "created_at": comp["created_at"]
                    })

                # Seed security classifications
                print("[SEED] Seeding security_classifications...")
                classifications = self._generate_security_classifications(120)
                for cls in classifications:
                    conn.execute(text("""
                        INSERT INTO zta.security_classifications
                        (session_id, original_label, predicted_threats, framework_type,
                         classification_accuracy, false_positive, false_negative, created_at)
                        VALUES (:session_id, :original_label, :predicted_threats, :framework_type,
                                :classification_accuracy, :false_positive, :false_negative, :created_at)
                    """), {
                        "session_id": cls["session_id"],
                        "original_label": cls["original_label"],
                        "predicted_threats": json.dumps(cls["predicted_threats"]),
                        "framework_type": cls["framework_type"],
                        "classification_accuracy": cls["classification_accuracy"],
                        "false_positive": cls["false_positive"],
                        "false_negative": cls["false_negative"],
                        "created_at": cls["created_at"]
                    })

                # Seed performance metrics
                print("[SEED] Seeding performance_metrics...")
                perf_metrics = self._generate_performance_metrics(200)
                for metric in perf_metrics:
                    conn.execute(text("""
                        INSERT INTO zta.performance_metrics
                        (session_id, service_name, operation, start_time, end_time, status, error_message)
                        VALUES (:session_id, :service_name, :operation, :start_time, :end_time, :status, :error_message)
                    """), metric)

                # Seed MFA events
                print("[SEED] Seeding mfa_events...")
                mfa_events = self._generate_mfa_events(100)
                for event in mfa_events:
                    conn.execute(text("""
                        INSERT INTO zta.mfa_events
                        (session_id, outcome, detail, created_at)
                        VALUES (:session_id, :outcome, :detail, :created_at)
                    """), {
                        "session_id": event["session_id"],
                        "outcome": event["outcome"],
                        "detail": json.dumps(event["detail"]),
                        "created_at": event["created_at"]
                    })

                print("[SEED] Database seeding completed successfully!")

                # Print summary
                print("\n[SUMMARY] Seeded data:")
                print("  - 100 baseline decisions")
                print("  - 150 baseline auth attempts")
                print("  - 80 framework comparisons")
                print("  - 120 security classifications")
                print("  - 200 performance metrics")
                print("  - 100 MFA events")

        except Exception as e:
            print(f"[SEED] Seeding failed: {e}")
            raise

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="Database Seeding Script")
    parser.add_argument("--db-dsn", default=os.getenv("DB_DSN", "postgresql://postgres:password@localhost:5432/postgres"), help="Database DSN")

    args = parser.parse_args()

    # Use the DSN from args
    db_dsn = args.db_dsn

    try:
        seeder = DatabaseSeeder(dsn=db_dsn)
        seeder.seed_all_tables()
        print("\n[SUCCESS] Database seeded successfully!")

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Seeding interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Seeding failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
