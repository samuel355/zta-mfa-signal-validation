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

    def run_indexing_cycle(self):
        """Run one complete indexing cycle"""
        logger.info("Starting indexing cycle...")

        try:
            # Index all data types
            self.index_framework_comparison_data()
            self.index_security_classifications_data()

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
