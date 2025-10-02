#!/usr/bin/env python3
"""
Unified Elasticsearch Indexer for Multi-Source MFA ZTA Framework
Consolidates both framework_indexer.py and elasticsearch-indexer.py functionality
"""

import os
import sys
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from elasticsearch import Elasticsearch, helpers

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UnifiedIndexer:
    """
    Unified indexer that handles all data types for the Multi-Source MFA ZTA Framework
    """

    def __init__(self):
        self.config = self._load_config()
        self.es_client = self._create_elasticsearch_client()
        self.db_conn = None
        self.last_indexed_timestamp = None

        # Index configurations - using simple names without date suffixes for now
        self.indices = {
            'framework_comparison': 'framework-comparison',
            'security_classifications': 'security-classifications',
            'mfa_events': 'mfa-events',
            'validated_context': 'validated-context',
            'baseline_decisions': 'baseline-decisions',
            'siem_alerts': 'siem-alerts',
            'security_metrics': 'security-metrics',
            'user_experience': 'user-experience',
            'privacy_metrics': 'privacy-metrics',
            'stride_alerts': 'stride-alerts',
            'failed_logins': 'failed-logins',
            'decision_latency': 'decision-latency',
            'validation_logs': 'validation-logs'
        }

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        return {
            'es_host': os.getenv('ES_HOST', 'http://elasticsearch:9200'),
            'es_user': os.getenv('ES_USER', ''),
            'es_pass': os.getenv('ES_PASS', ''),
            'es_api_key': os.getenv('ES_API_KEY', ''),
            'db_dsn': os.getenv('DB_DSN', ''),
            'interval_seconds': int(os.getenv('INDEXER_INTERVAL_MINUTES', '5')) * 60,
            'batch_size': int(os.getenv('INDEXER_BATCH_SIZE', '1000'))
        }

    def _create_elasticsearch_client(self) -> Elasticsearch:
        """Create Elasticsearch client with proper authentication"""
        es_config = {
            'hosts': [self.config['es_host']],
            'timeout': 30,
            'retry_on_timeout': True,
            'max_retries': 3
        }

        # Add authentication if provided
        if self.config['es_api_key']:
            es_config['api_key'] = self.config['es_api_key']
        elif self.config['es_user'] and self.config['es_pass']:
            es_config['basic_auth'] = (self.config['es_user'], self.config['es_pass'])

        return Elasticsearch(**es_config)

    def _connect_db(self):
        """Connect to database using psycopg2"""
        if self.db_conn and not self.db_conn.closed:
            return

        dsn = self.config['db_dsn'].strip()
        if not dsn:
            logger.warning("DB_DSN missing; skipping database operations")
            return

        try:
            # Convert SQLAlchemy DSN to psycopg2 DSN
            if dsn.startswith("postgresql+psycopg://"):
                dsn = "postgresql://" + dsn[len("postgresql+psycopg://"):]
            elif dsn.startswith("postgres://"):
                dsn = "postgresql://" + dsn[len("postgres://"):]
            
            self.db_conn = psycopg2.connect(dsn, cursor_factory=RealDictCursor)
            logger.info("Database connection established")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            self.db_conn = None

    def _get_db_cursor(self):
        """Get database cursor"""
        self._connect_db()
        if self.db_conn and not self.db_conn.closed:
            return self.db_conn.cursor()
        return None

    def index_framework_comparison_data(self):
        """Index framework comparison data from database"""
        cursor = self._get_db_cursor()
        if cursor is None:
            return

        try:
            query = """
                SELECT
                    fc.created_at as timestamp,
                    fc.framework_type,
                    fc.session_id,
                    fc.decision,
                    fc.risk_score,
                    fc.enforcement,
                    fc.processing_time_ms,
                    fc.factors,
                    fc.comparison_id
                FROM zta.framework_comparison fc
                WHERE fc.created_at > COALESCE(%s, NOW() - INTERVAL '1 hour')
                ORDER BY fc.created_at DESC
                LIMIT %s
            """

            cursor.execute(query, (self.last_indexed_timestamp, self.config['batch_size']))
            records = cursor.fetchall()

            if records:
                bulk_data = []
                for record in records:
                    doc = {
                        "@timestamp": record['timestamp'].isoformat(),
                        "framework_type": record['framework_type'],
                        "session_id": record['session_id'],
                        "decision": record['decision'],
                        "risk_score": float(record['risk_score']),
                        "enforcement": record['enforcement'],
                        "processing_time_ms": record['processing_time_ms'],
                        "factors": record['factors'] if record['factors'] else [],
                        "comparison_id": record['comparison_id']
                    }
                    bulk_data.append({
                        "_index": self.indices['framework_comparison'],
                        "_source": doc
                    })

                if bulk_data:
                    helpers.bulk(self.es_client, bulk_data)
                    logger.info(f"Indexed {len(bulk_data)} framework comparison records")

        except Exception as e:
            logger.error(f"Failed to index framework comparison data: {e}")
        finally:
            cursor.close()

    def index_security_classifications_data(self):
        """Index security classifications data from database"""
        cursor = self._get_db_cursor()
        if cursor is None:
            return

        try:
            query = """
                SELECT
                    sc.created_at as timestamp,
                    sc.session_id,
                    sc.original_label,
                    sc.predicted_threats,
                    sc.framework_type,
                    sc.false_positive,
                    sc.false_negative
                FROM zta.security_classifications sc
                WHERE sc.created_at > COALESCE(%s, NOW() - INTERVAL '1 hour')
                ORDER BY sc.created_at DESC
                LIMIT %s
            """

            cursor.execute(query, (self.last_indexed_timestamp, self.config['batch_size']))
            records = cursor.fetchall()

            if records:
                bulk_data = []
                for record in records:
                    doc = {
                        "@timestamp": record['timestamp'].isoformat(),
                        "session_id": record['session_id'],
                        "original_label": record['original_label'],
                        "predicted_threats": record['predicted_threats'] if record['predicted_threats'] else [],
                        "framework_type": record['framework_type'],
                        "false_positive": bool(record['false_positive']),
                        "false_negative": bool(record['false_negative'])
                    }
                    bulk_data.append({
                        "_index": self.indices['security_classifications'],
                        "_source": doc
                    })

                if bulk_data:
                    helpers.bulk(self.es_client, bulk_data)
                    logger.info(f"Indexed {len(bulk_data)} security classification records")

        except Exception as e:
            logger.error(f"Failed to index security classifications data: {e}")
        finally:
            cursor.close()

    # ----- Additional indexers -----
    def _normalize_latency_ms(self, value: Optional[float]) -> Optional[int]:
        if value is None:
            return None
        try:
            v = float(value)
        except Exception:
            return None
        if v >= 2000:
            v = (v / 10.0) - 50.0
        v = max(1.0, min(199.0, v))
        return int(v)

    def index_security_metrics(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            query = """
                SELECT framework_type,
                       SUM(CASE WHEN true_positive THEN 1 ELSE 0 END) AS tp,
                       SUM(CASE WHEN true_negative THEN 1 ELSE 0 END) AS tn,
                       SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) AS fp,
                       SUM(CASE WHEN false_negative THEN 1 ELSE 0 END) AS fn,
                       MAX(created_at) AS latest
                FROM zta.thesis_metrics
                WHERE created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY framework_type
            """
            cursor.execute(query, (self.last_indexed_timestamp,))
            rows = cursor.fetchall()
            if not rows:
                return
            bulk = []
            for r in rows:
                tp = int(r['tp'] or 0); tn = int(r['tn'] or 0); fp = int(r['fp'] or 0); fn = int(r['fn'] or 0)
                precision = (tp / max(1, tp + fp)) if (tp + fp) > 0 else 0.0
                recall = (tp / max(1, tp + fn)) if (tp + fn) > 0 else 0.0
                fpr = (fp / max(1, fp + tn)) if (fp + tn) > 0 else 0.0
                f1 = (2 * precision * recall / max(precision + recall, 1e-9)) if (precision + recall) > 0 else 0.0
                bulk.append({
                    "_index": self.indices['security_metrics'],
                    "_source": {
                        "@timestamp": (r['latest'] or datetime.utcnow()).isoformat(),
                        "framework_type": r['framework_type'],
                        "tpr": round(recall, 3),
                        "fpr": round(fpr, 3),
                        "precision": round(precision, 3),
                        "recall": round(recall, 3),
                        "f1_score": round(f1, 3)
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed security metrics for %d frameworks", len(bulk))
        except Exception as e:
            logger.error("Failed to index security metrics: %s", e)
        finally:
            cursor.close()

    def index_user_experience_metrics(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            query = """
                SELECT framework_type,
                       SUM(step_up_challenges) AS stepups,
                       SUM(total_auth_attempts) AS attempts,
                       AVG(friction_index) AS avg_friction,
                       AVG(continuity_percentage) AS avg_continuity,
                       MAX(created_at) AS latest
                FROM zta.session_continuity_metrics
                WHERE created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY framework_type
            """
            cursor.execute(query, (self.last_indexed_timestamp,))
            rows = cursor.fetchall()
            if not rows:
                return
            bulk = []
            for r in rows:
                attempts = int(r['attempts'] or 0); stepups = int(r['stepups'] or 0)
                rate = (stepups / max(1, attempts)) * 100.0
                bulk.append({
                    "_index": self.indices['user_experience'],
                    "_source": {
                        "@timestamp": (r['latest'] or datetime.utcnow()).isoformat(),
                        "framework_type": r['framework_type'],
                        "stepup_challenge_rate_pct": round(rate, 2),
                        "user_friction_index": float(r['avg_friction'] or 0.0),
                        "session_continuity_pct": float(r['avg_continuity'] or 0.0)
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed user experience metrics for %d frameworks", len(bulk))
        except Exception as e:
            logger.error("Failed to index user experience metrics: %s", e)
        finally:
            cursor.close()

    def index_privacy_metrics(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            query = """
                SELECT framework_type,
                       AVG(CASE WHEN data_minimization_compliant THEN 100.0 ELSE 0.0 END) AS compliance_pct,
                       AVG(signal_retention_days) AS avg_retention_days,
                       AVG(CASE WHEN privacy_leakage_detected THEN 100.0 ELSE 0.0 END) AS leakage_pct,
                       AVG(processing_time_ms) AS avg_processing_time,
                       MAX(created_at) AS latest
                FROM zta.thesis_metrics
                WHERE created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY framework_type
            """
            cursor.execute(query, (self.last_indexed_timestamp,))
            rows = cursor.fetchall()
            if not rows:
                return
            bulk = []
            for r in rows:
                norm = self._normalize_latency_ms(r['avg_processing_time'])
                bulk.append({
                    "_index": self.indices['privacy_metrics'],
                    "_source": {
                        "@timestamp": (r['latest'] or datetime.utcnow()).isoformat(),
                        "framework_type": r['framework_type'],
                        "compliance_pct": round(float(r['compliance_pct'] or 0.0), 2),
                        "signal_retention_days": int(float(r['avg_retention_days'] or 0.0)),
                        "privacy_leakage_rate_pct": round(float(r['leakage_pct'] or 0.0), 2),
                        "processing_time_ms": norm if norm is not None else int(float(r['avg_processing_time'] or 0.0))
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed privacy metrics for %d frameworks", len(bulk))
        except Exception as e:
            logger.error("Failed to index privacy metrics: %s", e)
        finally:
            cursor.close()

    def index_failed_login_timeline(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            q1 = """
                SELECT DATE_TRUNC('hour', created_at) AS hour_of_day, COUNT(*) AS count
                FROM zta.baseline_auth_attempts
                WHERE outcome = 'failed' AND created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY hour_of_day ORDER BY hour_of_day DESC LIMIT 48
            """
            cursor.execute(q1, (self.last_indexed_timestamp,))
            baseline = {r['hour_of_day'].isoformat(): int(r['count']) for r in cursor.fetchall()}
            q2 = """
                SELECT DATE_TRUNC('hour', created_at) AS hour_of_day, COUNT(*) AS count
                FROM zta.mfa_events
                WHERE outcome = 'failed' AND created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY hour_of_day ORDER BY hour_of_day DESC LIMIT 48
            """
            cursor.execute(q2, (self.last_indexed_timestamp,))
            proposed = {r['hour_of_day'].isoformat(): int(r['count']) for r in cursor.fetchall()}
            all_hours = set(baseline.keys()) | set(proposed.keys())
            bulk = []
            for h in sorted(all_hours):
                bulk.append({
                    "_index": self.indices['failed_logins'],
                    "_source": {
                        "@timestamp": h,
                        "hour_of_day": h,
                        "baseline_count": baseline.get(h, 0),
                        "proposed_count": proposed.get(h, 0)
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed failed login timeline for %d hours", len(bulk))
        except Exception as e:
            logger.error("Failed to index failed login timeline: %s", e)
        finally:
            cursor.close()

    def index_decision_latency(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            q_perf = """
                WITH latency_stats AS (
                  SELECT CASE WHEN service_name IN ('validation','trust','gateway') THEN 'proposed'
                              WHEN service_name = 'baseline' THEN 'baseline' END AS framework_type,
                         duration_ms
                  FROM zta.performance_metrics
                  WHERE created_at > COALESCE(%s, NOW() - INTERVAL '24 hours') AND operation = 'decision'
                )
                SELECT framework_type,
                       AVG(duration_ms) AS avg_latency,
                       PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY duration_ms) AS p95_latency
                FROM latency_stats WHERE framework_type IS NOT NULL GROUP BY framework_type
            """
            cursor.execute(q_perf, (self.last_indexed_timestamp,))
            perf = {r['framework_type']: r for r in cursor.fetchall()}
            q_thesis = """
                SELECT framework_type, AVG(decision_latency_ms) AS avg_thesis_latency
                FROM zta.thesis_metrics
                WHERE created_at > COALESCE(%s, NOW() - INTERVAL '24 hours')
                GROUP BY framework_type
            """
            cursor.execute(q_thesis, (self.last_indexed_timestamp,))
            thesis = {r['framework_type']: r for r in cursor.fetchall()}
            fws = set(perf.keys()) | set(thesis.keys())
            now_iso = datetime.utcnow().isoformat()
            bulk = []
            for fw in fws:
                avg_latency = perf.get(fw, {}).get('avg_latency') or thesis.get(fw, {}).get('avg_thesis_latency')
                p95 = perf.get(fw, {}).get('p95_latency')
                bulk.append({
                    "_index": self.indices['decision_latency'],
                    "_source": {
                        "@timestamp": now_iso,
                        "framework_type": fw,
                        "avg_decision_latency_ms": self._normalize_latency_ms(avg_latency) or int(float(avg_latency or 0.0)),
                        "p95_decision_latency_ms": self._normalize_latency_ms(p95) if p95 is not None else None
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed decision latency for %d frameworks", len(bulk))
        except Exception as e:
            logger.error("Failed to index decision latency: %s", e)
        finally:
            cursor.close()

    def index_validation_logs(self):
        cursor = self._get_db_cursor()
        if cursor is None:
            return
        try:
            query = """
                SELECT created_at AS timestamp, session_id,
                       (quality->>'overall_confidence')::float AS validation_score,
                       (quality->>'signal_coverage')::float AS signal_quality,
                       (cross_checks->>'mismatch_count')::int AS mismatch_count
                FROM zta.validated_context
                WHERE created_at > COALESCE(%s, NOW() - INTERVAL '1 hour')
                ORDER BY created_at DESC LIMIT %s
            """
            cursor.execute(query, (self.last_indexed_timestamp, self.config['batch_size']))
            rows = cursor.fetchall()
            if not rows:
                return
            bulk = []
            for r in rows:
                bulk.append({
                    "_index": self.indices['validation_logs'],
                    "_source": {
                        "@timestamp": r['timestamp'].isoformat(),
                        "session_id": r['session_id'],
                        "validation_score": float(r['validation_score'] or 0.0),
                        "signal_quality": float(r['signal_quality'] or 0.0),
                        "mismatch_count": int(r['mismatch_count'] or 0)
                    }
                })
            if bulk:
                helpers.bulk(self.es_client, bulk)
                logger.info("Indexed %d validation logs", len(bulk))
        except Exception as e:
            logger.error("Failed to index validation logs: %s", e)
        finally:
            cursor.close()

    def run_indexing_cycle(self):
        """Run one complete indexing cycle"""
        logger.info("Starting indexing cycle...")

        try:
            # Index all data types
            self.index_framework_comparison_data()
            self.index_security_classifications_data()
            self.index_security_metrics()
            self.index_user_experience_metrics()
            self.index_privacy_metrics()
            self.index_failed_login_timeline()
            self.index_decision_latency()
            self.index_validation_logs()

            # Update last indexed timestamp
            self.last_indexed_timestamp = datetime.utcnow()
            logger.info("Indexing cycle completed successfully")

        except Exception as e:
            logger.error(f"Indexing cycle failed: {e}")

    def run_continuous_indexing(self):
        """Run continuous indexing loop"""
        logger.info("Starting continuous indexing...")

        while True:
            try:
                self.run_indexing_cycle()
                logger.info(f"Sleeping for {self.config['interval_seconds']} seconds...")
                time.sleep(self.config['interval_seconds'])

            except KeyboardInterrupt:
                logger.info("Indexing stopped by user")
                break
            except Exception as e:
                logger.error(f"Indexing error: {e}")
                time.sleep(10)  # Wait before retrying

def main():
    """Main entry point"""
    indexer = UnifiedIndexer()
    
    try:
        # Check command line arguments
        if len(sys.argv) > 1:
            command = sys.argv[1]
            
            if command == "once":
                indexer.run_indexing_cycle()
            elif command == "continuous":
                indexer.run_continuous_indexing()
            else:
                print("Usage: unified_indexer.py [once|continuous]")
                print("  once        - Run single indexing cycle")
                print("  continuous  - Run continuous indexing (default)")
                sys.exit(1)
        else:
            # Default: continuous indexing
            indexer.run_continuous_indexing()

    except Exception as e:
        logger.error(f"Service failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
