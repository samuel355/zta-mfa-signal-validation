#!/usr/bin/env python3
"""
Elasticsearch Data Indexing Service for Multi-Source MFA ZTA Framework Thesis
Automatically indexes metrics data from the database to Elasticsearch for Kibana analysis
"""


import time
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any
import requests
from elasticsearch import Elasticsearch, helpers
import psycopg2
from psycopg2.extras import RealDictCursor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ElasticsearchIndexer:
    """Service for indexing thesis metrics data to Elasticsearch"""

    def __init__(self, config: Dict[str, str]):
        self.config = config
        self.es_client = self._create_es_client()
        self.db_connection = None
        self.running = False

        # Index configurations
        self.indices = {
            'thesis-metrics': 'thesis-metrics-{date}',
            'framework-comparison': 'framework-comparison-{date}',
            'security-classifications': 'security-classifications-{date}',
            'performance-metrics': 'performance-metrics-{date}',
            'failed-login-attempts': 'failed-login-attempts-{date}',
            'usability-data': 'usability-data-{date}',
            'privacy-data': 'privacy-data-{date}'
        }

    def _create_es_client(self) -> Elasticsearch:
        """Create Elasticsearch client with proper authentication"""
        es_config = {
            'hosts': [self.config.get('ES_HOST', 'http://localhost:9200')],
            'request_timeout': 30,
            'max_retries': 3,
            'retry_on_timeout': True
        }

        # Add authentication if provided
        if self.config.get('ES_USER') and self.config.get('ES_PASS'):
            es_config['basic_auth'] = (
                self.config['ES_USER'],
                self.config['ES_PASS']
            )
        elif self.config.get('ES_API_KEY'):
            es_config['api_key'] = self.config['ES_API_KEY']

        return Elasticsearch(**es_config)

    def _connect_database(self):
        """Connect to PostgreSQL database"""
        try:
            # Get raw DSN
            dsn = self.config.get('DB_DSN', 'postgresql://postgres:password@localhost:5432/zta_framework')

            # Convert SQLAlchemy format to psycopg2 format
            if dsn.startswith("postgresql+psycopg://"):
                dsn = dsn.replace('postgresql+psycopg://', 'postgresql://')
            elif dsn.startswith("postgres://"):
                dsn = dsn.replace('postgres://', 'postgresql://')

            # Ensure sslmode is set for remote connections
            if 'supabase.com' in dsn and 'sslmode=' not in dsn:
                dsn += ("&" if "?" in dsn else "?") + "sslmode=require"

            conn = psycopg2.connect(dsn, cursor_factory=RealDictCursor)
            conn.autocommit = True
            return conn
        except Exception as e:
            logger.error(f"Database connection failed: {e}")
            raise

    def wait_for_services(self, max_attempts: int = 30) -> bool:
        """Wait for Elasticsearch and database to be available"""
        logger.info("Waiting for services to be available...")

        # Wait for Elasticsearch
        for attempt in range(max_attempts):
            try:
                if self.es_client.ping():
                    logger.info("Elasticsearch is available")
                    break
            except Exception as e:
                logger.debug(f"Elasticsearch not ready (attempt {attempt + 1}): {e}")
                time.sleep(5)
        else:
            logger.error("Elasticsearch is not available after maximum attempts")
            return False

        # Wait for database
        for attempt in range(max_attempts):
            try:
                conn = self._connect_database()
                conn.close()
                logger.info("Database is available")
                break
            except Exception as e:
                logger.debug(f"Database not ready (attempt {attempt + 1}): {e}")
                time.sleep(5)
        else:
            logger.error("Database is not available after maximum attempts")
            return False

        return True

    def create_index_templates(self):
        """Create Elasticsearch index templates"""
        templates = {
            'thesis-metrics-template': {
                'index_patterns': ['thesis-metrics-*'],
                'template': {
                    'settings': {
                        'number_of_shards': 1,
                        'number_of_replicas': 1,
                        'refresh_interval': '30s'
                    },
                    'mappings': {
                        'properties': {
                            '@timestamp': {'type': 'date'},
                            'metric_type': {'type': 'keyword'},
                            'framework': {'type': 'keyword'},
                            'analysis_period_hours': {'type': 'integer'},
                            'tpr': {'type': 'float'},
                            'fpr': {'type': 'float'},
                            'precision': {'type': 'float'},
                            'recall': {'type': 'float'},
                            'f1_score': {'type': 'float'},
                            'accuracy': {'type': 'float'},
                            'avg_decision_latency_ms': {'type': 'float'},
                            'p95_latency_ms': {'type': 'float'},
                            'throughput_rps': {'type': 'float'},
                            'cpu_utilization_pct': {'type': 'float'},
                            'memory_utilization_mb': {'type': 'float'},
                            'success_rate': {'type': 'float'},
                            'step_up_challenge_rate_pct': {'type': 'float'},
                            'user_friction_index': {'type': 'float'},
                            'session_continuity_pct': {'type': 'float'},
                            'data_minimization_compliance_pct': {'type': 'float'},
                            'privacy_leakage_rate_pct': {'type': 'float'}
                        }
                    }
                }
            },
            'framework-comparison-template': {
                'index_patterns': ['framework-comparison-*'],
                'template': {
                    'settings': {
                        'number_of_shards': 1,
                        'number_of_replicas': 1,
                        'refresh_interval': '10s'
                    },
                    'mappings': {
                        'properties': {
                            '@timestamp': {'type': 'date'},
                            'comparison_id': {'type': 'keyword'},
                            'framework_type': {'type': 'keyword'},
                            'session_id': {'type': 'keyword'},
                            'decision': {'type': 'keyword'},
                            'risk_score': {'type': 'float'},
                            'processing_time_ms': {'type': 'integer'},
                            'factors': {'type': 'nested'},
                            'ip_address': {'type': 'ip'},
                            'location': {'type': 'geo_point'}
                        }
                    }
                }
            },
            'security-classifications-template': {
                'index_patterns': ['security-classifications-*'],
                'template': {
                    'settings': {
                        'number_of_shards': 1,
                        'number_of_replicas': 1
                    },
                    'mappings': {
                        'properties': {
                            '@timestamp': {'type': 'date'},
                            'session_id': {'type': 'keyword'},
                            'framework_type': {'type': 'keyword'},
                            'original_label': {'type': 'keyword'},
                            'predicted_threats': {'type': 'keyword'},
                            'actual_threats': {'type': 'keyword'},
                            'classification_accuracy': {'type': 'float'},
                            'false_positive': {'type': 'boolean'},
                            'false_negative': {'type': 'boolean'},
                            'threat_severity': {'type': 'keyword'},
                            'confidence_score': {'type': 'float'}
                        }
                    }
                }
            }
        }

        for template_name, template_config in templates.items():
            try:
                self.es_client.indices.put_index_template(
                    name=template_name,
                    body=template_config
                )
                logger.info(f"Created index template: {template_name}")
            except Exception as e:
                logger.error(f"Failed to create template {template_name}: {e}")

    def get_thesis_metrics_from_api(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get comprehensive thesis metrics from the metrics API"""
        try:
            metrics_url = self.config.get('METRICS_URL', 'http://localhost:8030')
            response = requests.get(
                f"{metrics_url}/thesis/elasticsearch-export?hours={hours}",
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                return data.get('documents', [])
            else:
                logger.error(f"Failed to get metrics from API: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error getting metrics from API: {e}")
            return []

    def get_framework_comparison_data(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get framework comparison data from database"""
        if not self.db_connection:
            self.db_connection = self._connect_database()

        try:
            with self.db_connection.cursor() as cursor:
                query = """
                    SELECT
                        id,
                        comparison_id,
                        framework_type,
                        session_id,
                        decision,
                        risk_score,
                        enforcement,
                        factors,
                        processing_time_ms,
                        created_at
                    FROM zta.framework_comparison
                    WHERE created_at > NOW() - INTERVAL '%s hours'
                    ORDER BY created_at DESC
                """

                cursor.execute(query, (hours,))
                rows = cursor.fetchall()

                documents = []
                for row in rows:
                    # Convert RealDictRow to regular dict to avoid type issues
                    row_dict = dict(row)
                    doc = {
                        '@timestamp': row_dict['created_at'].isoformat(),
                        'comparison_id': row_dict['comparison_id'],
                        'framework_type': row_dict['framework_type'],
                        'session_id': row_dict['session_id'],
                        'decision': row_dict['decision'],
                        'risk_score': float(row_dict['risk_score']),
                        'enforcement': row_dict['enforcement'],
                        'processing_time_ms': row_dict['processing_time_ms'],
                        'factors': row_dict['factors'] if row_dict['factors'] else []
                    }
                    documents.append(doc)

                return documents

        except Exception as e:
            logger.error(f"Error getting framework comparison data: {e}")
            return []

    def get_security_classifications_data(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get security classifications data from database"""
        if not self.db_connection:
            self.db_connection = self._connect_database()

        try:
            with self.db_connection.cursor() as cursor:
                query = """
                    SELECT
                        session_id,
                        original_label,
                        predicted_threats,
                        actual_threats,
                        framework_type,
                        classification_accuracy,
                        false_positive,
                        false_negative,
                        created_at
                    FROM zta.security_classifications
                    WHERE created_at > NOW() - INTERVAL '%s hours'
                    ORDER BY created_at DESC
                """

                cursor.execute(query, (hours,))
                rows = cursor.fetchall()

                documents = []
                for row in rows:
                    # Convert RealDictRow to regular dict to avoid type issues
                    row_dict = dict(row)
                    doc = {
                        '@timestamp': row_dict['created_at'].isoformat(),
                        'session_id': row_dict['session_id'],
                        'framework_type': row_dict['framework_type'],
                        'original_label': row_dict['original_label'],
                        'predicted_threats': row_dict['predicted_threats'] if row_dict['predicted_threats'] else [],
                        'actual_threats': row_dict['actual_threats'] if row_dict['actual_threats'] else [],
                        'classification_accuracy': float(row_dict['classification_accuracy'] or 0),
                        'false_positive': row_dict['false_positive'],
                        'false_negative': row_dict['false_negative']
                    }
                    documents.append(doc)

                return documents

        except Exception as e:
            logger.error(f"Error getting security classifications data: {e}")
            return []

    def get_performance_metrics_data(self, hours: int = 1) -> List[Dict[str, Any]]:
        """Get performance metrics data from database"""
        if not self.db_connection:
            self.db_connection = self._connect_database()

        try:
            with self.db_connection.cursor() as cursor:
                query = """
                    SELECT
                        session_id,
                        service_name,
                        operation,
                        duration_ms,
                        start_time,
                        end_time,
                        status,
                        error_message,
                        created_at
                    FROM zta.performance_metrics
                    WHERE created_at > NOW() - INTERVAL '%s hours'
                    ORDER BY created_at DESC
                """

                cursor.execute(query, (hours,))
                rows = cursor.fetchall()

                documents = []
                for row in rows:
                    # Convert RealDictRow to regular dict to avoid type issues
                    row_dict = dict(row)
                    doc = {
                        '@timestamp': row_dict['created_at'].isoformat(),
                        'session_id': row_dict['session_id'],
                        'service_name': row_dict['service_name'],
                        'operation': row_dict['operation'],
                        'duration_ms': row_dict['duration_ms'],
                        'start_time': row_dict['start_time'].isoformat(),
                        'end_time': row_dict['end_time'].isoformat(),
                        'status': row_dict['status'],
                        'error_message': row_dict['error_message']
                    }
                    documents.append(doc)

                return documents

        except Exception as e:
            logger.error(f"Error getting performance metrics data: {e}")
            return []

    def index_documents(self, index_name: str, documents: List[Dict[str, Any]]) -> bool:
        """Index documents to Elasticsearch"""
        if not documents:
            logger.info(f"No documents to index for {index_name}")
            return True

        try:
            # Generate index name with current date
            current_date = datetime.now().strftime('%Y-%m-%d')
            full_index_name = index_name.format(date=current_date)

            # Prepare documents for bulk indexing
            actions = []
            for doc in documents:
                action = {
                    '_index': full_index_name,
                    '_source': doc
                }
                actions.append(action)

            # Bulk index documents
            result = helpers.bulk(
                self.es_client,
                actions,
                chunk_size=100,
                request_timeout=60
            )

            # Handle different return types from bulk helper
            if isinstance(result, tuple) and len(result) >= 2:
                success_count, failed_items = result[0], result[1]
            else:
                # If bulk returns just success count
                success_count = result if isinstance(result, int) else 0
                failed_items = []

            logger.info(f"Indexed {success_count} documents to {full_index_name}")

            if failed_items and isinstance(failed_items, list):
                logger.warning(f"Failed to index {len(failed_items)} documents")
                # Log first 5 failures for debugging
                for i, item in enumerate(failed_items[:5]):
                    logger.warning(f"Failed item {i+1}: {item}")
                return len(failed_items) == 0
            elif failed_items:
                logger.warning(f"Bulk indexing returned unexpected failed_items type: {type(failed_items)}")
                return False

            return True

        except Exception as e:
            logger.error(f"Error indexing documents to {index_name}: {e}")
            return False

    def run_indexing_cycle(self, hours: int = 1):
        """Run a single indexing cycle"""
        logger.info(f"Starting indexing cycle for last {hours} hours")

        try:
            # Index thesis metrics from API
            thesis_metrics = self.get_thesis_metrics_from_api(hours)
            if thesis_metrics:
                self.index_documents('thesis-metrics-{date}', thesis_metrics)

            # Index framework comparison data
            comparison_data = self.get_framework_comparison_data(hours)
            if comparison_data:
                self.index_documents('framework-comparison-{date}', comparison_data)

            # Index security classifications
            security_data = self.get_security_classifications_data(hours)
            if security_data:
                self.index_documents('security-classifications-{date}', security_data)

            # Index performance metrics
            performance_data = self.get_performance_metrics_data(hours)
            if performance_data:
                self.index_documents('performance-metrics-{date}', performance_data)

            logger.info("Indexing cycle completed successfully")

        except Exception as e:
            logger.error(f"Error during indexing cycle: {e}")

    def start_continuous_indexing(self, interval_minutes: int = 5, batch_hours: int = 1):
        """Start continuous indexing process"""
        self.running = True
        logger.info(f"Starting continuous indexing (interval: {interval_minutes}min, batch: {batch_hours}h)")

        try:
            while self.running:
                self.run_indexing_cycle(batch_hours)

                if self.running:  # Check again in case stop was called during indexing
                    logger.info(f"Sleeping for {interval_minutes} minutes...")
                    time.sleep(interval_minutes * 60)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal, stopping...")
            self.running = False
        except Exception as e:
            logger.error(f"Continuous indexing failed: {e}")
            self.running = False
        finally:
            self.stop()

    def stop(self):
        """Stop the indexing service"""
        logger.info("Stopping indexing service...")
        self.running = False

        if self.db_connection:
            self.db_connection.close()
            self.db_connection = None

    def run_historical_indexing(self, days: int = 7):
        """Index historical data for the past N days"""
        logger.info(f"Starting historical indexing for past {days} days")

        for day in range(days):
            date_offset = timedelta(days=day)
            target_date = datetime.now() - date_offset

            logger.info(f"Indexing data for {target_date.strftime('%Y-%m-%d')}")

            # Index data in 6-hour batches for the target day
            for hour_offset in range(0, 24, 6):
                batch_hours = min(6, 24 - hour_offset)
                self.run_indexing_cycle(batch_hours)
                time.sleep(2)  # Small delay between batches

        logger.info("Historical indexing completed")

def load_config() -> Dict[str, str]:
    """Load configuration from environment variables"""
    config = {
        'ES_HOST': os.getenv('ES_HOST', 'http://localhost:9200'),
        'ES_USER': os.getenv('ES_USER', 'elastic'),
        'ES_PASS': os.getenv('ES_PASS', 'changeme'),
        'DB_DSN': os.getenv('DB_DSN', 'postgresql://postgres:password@localhost:5432/zta_framework'),
        'METRICS_URL': os.getenv('METRICS_URL', 'http://localhost:8030')
    }

    # Handle optional API key
    api_key = os.getenv('ES_API_KEY')
    if api_key:
        config['ES_API_KEY'] = api_key

    return config

def main():
    """Main entry point"""
    config = load_config()

    logger.info("Starting Elasticsearch Indexer Service")
    logger.info(f"Elasticsearch: {config['ES_HOST']}")
    logger.info(f"Metrics API: {config['METRICS_URL']}")

    indexer = ElasticsearchIndexer(config)

    try:
        # Wait for services to be available
        if not indexer.wait_for_services():
            logger.error("Required services are not available")
            sys.exit(1)

        # Create index templates
        indexer.create_index_templates()

        # Check command line arguments
        if len(sys.argv) > 1:
            command = sys.argv[1]

            if command == "historical":
                days = int(sys.argv[2]) if len(sys.argv) > 2 else 7
                indexer.run_historical_indexing(days)
            elif command == "once":
                hours = int(sys.argv[2]) if len(sys.argv) > 2 else 24
                indexer.run_indexing_cycle(hours)
            elif command == "continuous":
                interval = int(sys.argv[2]) if len(sys.argv) > 2 else 5
                batch_hours = int(sys.argv[3]) if len(sys.argv) > 3 else 1
                indexer.start_continuous_indexing(interval, batch_hours)
            else:
                print("Usage: elasticsearch-indexer.py [historical|once|continuous] [args...]")
                print("  historical [days]     - Index historical data")
                print("  once [hours]          - Run single indexing cycle")
                print("  continuous [interval] [batch_hours] - Run continuous indexing")
                sys.exit(1)
        else:
            # Default: continuous indexing
            indexer.start_continuous_indexing()

    except Exception as e:
        logger.error(f"Service failed: {e}")
        sys.exit(1)
    finally:
        indexer.stop()

if __name__ == "__main__":
    main()
