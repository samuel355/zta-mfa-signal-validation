#!/usr/bin/env python3
"""
Kibana Dashboard Setup for Multi-Source MFA ZTA Framework
Creates comprehensive dashboards for visualizing authentication metrics and framework comparison
"""

import os
import sys
import json
import time
import logging
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DashboardSetup:
    """Sets up Kibana dashboards for framework analysis"""

    def __init__(self):
        self.kibana_url = os.getenv('KIBANA_URL', 'http://localhost:5601')
        self.kibana_user = os.getenv('KIBANA_USER', '')
        self.kibana_pass = os.getenv('KIBANA_PASS', '')
        self.space_id = os.getenv('KIBANA_SPACE', 'default')

        # Dashboard configurations
        self.dashboards = []
        self.visualizations = []
        self.index_patterns = []

    def _make_kibana_request(self, method: str, endpoint: str, data: Dict = None) -> Optional[Dict]:
        """Make authenticated request to Kibana API"""
        url = f"{self.kibana_url}/api/{endpoint}"
        headers = {
            'kbn-xsrf': 'true',
            'Content-Type': 'application/json'
        }

        auth = None
        if self.kibana_user and self.kibana_pass:
            auth = (self.kibana_user, self.kibana_pass)

        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, auth=auth)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, auth=auth)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, auth=auth)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, auth=auth)

            response.raise_for_status()
            return response.json() if response.content else None

        except requests.exceptions.RequestException as e:
            logger.error(f"Kibana request failed: {e}")
            return None

    def create_index_patterns(self):
        """Create index patterns for all data indices"""

        index_patterns = [
            {
                'title': 'framework-comparison*',
                'timeFieldName': '@timestamp',
                'name': 'Framework Comparison'
            },
            {
                'title': 'security-metrics*',
                'timeFieldName': '@timestamp',
                'name': 'Security Metrics'
            },
            {
                'title': 'user-experience*',
                'timeFieldName': '@timestamp',
                'name': 'User Experience'
            },
            {
                'title': 'privacy-metrics*',
                'timeFieldName': '@timestamp',
                'name': 'Privacy Metrics'
            },
            {
                'title': 'stride-alerts*',
                'timeFieldName': '@timestamp',
                'name': 'STRIDE Alerts'
            },
            {
                'title': 'failed-logins*',
                'timeFieldName': '@timestamp',
                'name': 'Failed Logins'
            },
            {
                'title': 'decision-latency*',
                'timeFieldName': '@timestamp',
                'name': 'Decision Latency'
            },
            {
                'title': 'validation-logs*',
                'timeFieldName': '@timestamp',
                'name': 'Validation Logs'
            }
        ]

        for pattern in index_patterns:
            logger.info(f"Creating index pattern: {pattern['title']}")

            data = {
                'data_view': {
                    'title': pattern['title'],
                    'name': pattern['name'],
                    'timeFieldName': pattern['timeFieldName']
                }
            }

            result = self._make_kibana_request('POST', 'data_views/data_view', data)
            if result:
                logger.info(f"✅ Created index pattern: {pattern['name']}")
                self.index_patterns.append(result)
            else:
                logger.warning(f"Failed to create index pattern: {pattern['name']}")

    def create_security_accuracy_visualization(self):
        """Create security accuracy metrics visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Security Accuracy Metrics',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': True, 'position': 'right'},
                        'valueLabels': 'hide',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True,
                            'yRight': False
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True,
                            'yRight': False
                        },
                        'labelsOrientation': {
                            'x': 0,
                            'yLeft': 0,
                            'yRight': 0
                        },
                        'gridlinesVisibilitySettings': {
                            'x': True,
                            'yLeft': True,
                            'yRight': False
                        },
                        'preferredSeriesType': 'bar_grouped',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'layerType': 'data',
                                'seriesType': 'bar_grouped',
                                'xAccessor': 'metric',
                                'accessors': ['baseline_value', 'proposed_value'],
                                'yConfig': [
                                    {'forAccessor': 'baseline_value', 'color': '#FFA500'},
                                    {'forAccessor': 'proposed_value', 'color': '#4169E1'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'metric': {
                                            'label': 'Metric',
                                            'dataType': 'string',
                                            'operationType': 'terms',
                                            'sourceField': 'metric_type.keyword',
                                            'params': {
                                                'size': 5,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'baseline_value': {
                                            'label': 'Baseline',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'baseline_value'
                                        },
                                        'proposed_value': {
                                            'label': 'Proposed',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'proposed_value'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'security-metrics*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_failed_login_timeline_visualization(self):
        """Create failed login timeline visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Failed Login Attempts Timeline',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': True, 'position': 'top'},
                        'valueLabels': 'hide',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'line',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'line',
                                'xAccessor': 'hour_of_day',
                                'accessors': ['baseline_logins', 'proposed_logins'],
                                'yConfig': [
                                    {'forAccessor': 'baseline_logins', 'color': '#FFA500'},
                                    {'forAccessor': 'proposed_logins', 'color': '#4169E1'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'hour_of_day': {
                                            'label': 'Hour of Day',
                                            'dataType': 'number',
                                            'operationType': 'terms',
                                            'sourceField': 'hour_of_day',
                                            'params': {
                                                'size': 24,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'baseline_logins': {
                                            'label': 'Baseline Logins',
                                            'dataType': 'number',
                                            'operationType': 'sum',
                                            'sourceField': 'baseline_count'
                                        },
                                        'proposed_logins': {
                                            'label': 'Proposed Failed Logins',
                                            'dataType': 'number',
                                            'operationType': 'sum',
                                            'sourceField': 'proposed_count'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'failed-logins*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_stepup_challenge_rate_visualization(self):
        """Create step-up challenge rate comparison visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Step-up Challenge Rate (%)',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': False},
                        'valueLabels': 'inside',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': False,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': False,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'bar',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'bar',
                                'xAccessor': 'framework',
                                'accessors': ['challenge_rate'],
                                'yConfig': [
                                    {
                                        'forAccessor': 'challenge_rate',
                                        'color': {
                                            'stops': [
                                                {'stop': 0, 'color': '#FFA500'},
                                                {'stop': 50, 'color': '#008000'}
                                            ]
                                        }
                                    }
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'framework': {
                                            'label': 'Framework',
                                            'dataType': 'string',
                                            'operationType': 'terms',
                                            'sourceField': 'framework_type.keyword',
                                            'params': {
                                                'size': 2,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'challenge_rate': {
                                            'label': 'Rate (%)',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'stepup_challenge_rate_pct'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'user-experience*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_stride_alerts_visualization(self):
        """Create STRIDE alerts distribution visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'STRIDE Alerts Distribution',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': False},
                        'valueLabels': 'inside',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': False,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'bar',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'bar',
                                'xAccessor': 'category',
                                'accessors': ['alert_count'],
                                'yConfig': [
                                    {'forAccessor': 'alert_count', 'color': '#87CEEB'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'category': {
                                            'label': 'STRIDE Category',
                                            'dataType': 'string',
                                            'operationType': 'terms',
                                            'sourceField': 'stride_category.keyword',
                                            'params': {
                                                'size': 6,
                                                'orderBy': {
                                                    'type': 'column',
                                                    'columnId': 'alert_count'
                                                },
                                                'orderDirection': 'desc'
                                            }
                                        },
                                        'alert_count': {
                                            'label': 'Alert Count',
                                            'dataType': 'number',
                                            'operationType': 'count',
                                            'sourceField': 'Records'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'stride-alerts*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_decision_latency_visualization(self):
        """Create decision latency under network conditions visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Decision Latency under Network Conditions',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': True, 'position': 'top'},
                        'valueLabels': 'hide',
                        'fittingFunction': 'Linear',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'line',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'line',
                                'xAccessor': 'network_latency',
                                'accessors': ['baseline_latency', 'proposed_latency'],
                                'yConfig': [
                                    {'forAccessor': 'baseline_latency', 'color': '#FFA500'},
                                    {'forAccessor': 'proposed_latency', 'color': '#4169E1'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'network_latency': {
                                            'label': 'Network Latency (ms)',
                                            'dataType': 'number',
                                            'operationType': 'terms',
                                            'sourceField': 'network_latency_ms',
                                            'params': {
                                                'size': 4,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'baseline_latency': {
                                            'label': 'Baseline',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'decision_latency_ms',
                                            'filter': {
                                                'query': 'framework_type: baseline',
                                                'language': 'kuery'
                                            }
                                        },
                                        'proposed_latency': {
                                            'label': 'Proposed',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'decision_latency_ms',
                                            'filter': {
                                                'query': 'framework_type: proposed',
                                                'language': 'kuery'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'decision-latency*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_privacy_metrics_visualization(self):
        """Create privacy safeguard metrics visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Privacy Safeguard Metrics',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': True, 'position': 'right'},
                        'valueLabels': 'inside',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': False,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'bar_grouped',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'bar_grouped',
                                'xAccessor': 'metric',
                                'accessors': ['baseline_value', 'proposed_value'],
                                'yConfig': [
                                    {'forAccessor': 'baseline_value', 'color': '#FFA500'},
                                    {'forAccessor': 'proposed_value', 'color': '#4169E1'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'metric': {
                                            'label': 'Metric',
                                            'dataType': 'string',
                                            'operationType': 'terms',
                                            'sourceField': 'privacy_metric_type.keyword',
                                            'params': {
                                                'size': 3,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'baseline_value': {
                                            'label': 'Baseline',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'value',
                                            'filter': {
                                                'query': 'framework_type: baseline',
                                                'language': 'kuery'
                                            }
                                        },
                                        'proposed_value': {
                                            'label': 'Proposed',
                                            'dataType': 'number',
                                            'operationType': 'average',
                                            'sourceField': 'value',
                                            'filter': {
                                                'query': 'framework_type: proposed',
                                                'language': 'kuery'
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'privacy-metrics*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_validation_mismatches_visualization(self):
        """Create context signal mismatches visualization"""

        viz_config = {
            'version': '8.11.0',
            'type': 'lens',
            'attributes': {
                'title': 'Context Signal Mismatches per Session',
                'visualizationType': 'lnsXY',
                'state': {
                    'visualization': {
                        'legend': {'isVisible': False},
                        'valueLabels': 'inside',
                        'fittingFunction': 'None',
                        'axisTitlesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'tickLabelsVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'gridlinesVisibilitySettings': {
                            'x': True,
                            'yLeft': True
                        },
                        'preferredSeriesType': 'bar',
                        'layers': [
                            {
                                'layerId': 'layer1',
                                'seriesType': 'bar',
                                'xAccessor': 'session',
                                'accessors': ['mismatch_count'],
                                'yConfig': [
                                    {'forAccessor': 'mismatch_count', 'color': '#FFA500'}
                                ]
                            }
                        ]
                    },
                    'query': {
                        'query': '',
                        'language': 'kuery'
                    },
                    'filters': [],
                    'datasourceStates': {
                        'formBased': {
                            'layers': {
                                'layer1': {
                                    'columns': {
                                        'session': {
                                            'label': 'Session ID',
                                            'dataType': 'string',
                                            'operationType': 'terms',
                                            'sourceField': 'session_id.keyword',
                                            'params': {
                                                'size': 20,
                                                'orderBy': {
                                                    'type': 'alphabetical'
                                                }
                                            }
                                        },
                                        'mismatch_count': {
                                            'label': 'Mismatch Count',
                                            'dataType': 'number',
                                            'operationType': 'max',
                                            'sourceField': 'mismatch_count'
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                'references': [
                    {
                        'type': 'index-pattern',
                        'id': 'validation-logs*',
                        'name': 'indexpattern-datasource-layer-layer1'
                    }
                ]
            }
        }

        return viz_config

    def create_main_dashboard(self):
        """Create the main framework comparison dashboard"""

        dashboard_config = {
            'version': '8.11.0',
            'type': 'dashboard',
            'attributes': {
                'title': 'Multi-Source MFA Framework Analysis',
                'description': 'Comprehensive comparison between baseline and proposed MFA frameworks',
                'panelsJSON': json.dumps([
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 0,
                            'y': 0,
                            'w': 24,
                            'h': 15,
                            'i': 'security-accuracy'
                        },
                        'panelConfig': {
                            'title': 'Security Accuracy Metrics'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_security_accuracy'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 24,
                            'y': 0,
                            'w': 24,
                            'h': 15,
                            'i': 'failed-logins'
                        },
                        'panelConfig': {
                            'title': 'Failed Login Timeline'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_failed_logins'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 0,
                            'y': 15,
                            'w': 16,
                            'h': 15,
                            'i': 'stepup-rate'
                        },
                        'panelConfig': {
                            'title': 'Step-up Challenge Rate'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_stepup_rate'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 16,
                            'y': 15,
                            'w': 16,
                            'h': 15,
                            'i': 'stride-alerts'
                        },
                        'panelConfig': {
                            'title': 'STRIDE Alerts'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_stride_alerts'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 32,
                            'y': 15,
                            'w': 16,
                            'h': 15,
                            'i': 'validation-mismatches'
                        },
                        'panelConfig': {
                            'title': 'Validation Mismatches'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_validation_mismatches'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 0,
                            'y': 30,
                            'w': 24,
                            'h': 15,
                            'i': 'decision-latency'
                        },
                        'panelConfig': {
                            'title': 'Decision Latency'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_decision_latency'
                    },
                    {
                        'version': '8.11.0',
                        'type': 'visualization',
                        'gridData': {
                            'x': 24,
                            'y': 30,
                            'w': 24,
                            'h': 15,
                            'i': 'privacy-metrics'
                        },
                        'panelConfig': {
                            'title': 'Privacy Metrics'
                        },
                        'embeddableConfig': {},
                        'panelRefName': 'panel_privacy_metrics'
                    }
                ]),
                'optionsJSON': json.dumps({
                    'useMargins': True,
                    'syncColors': False,
                    'hidePanelTitles': False
                }),
                'timeRestore': True,
                'timeTo': 'now',
                'timeFrom': 'now-24h',
                'refreshInterval': {
                    'pause': False,
                    'value': 30000
                }
            },
            'references': [
                {
                    'name': 'panel_security_accuracy',
                    'type': 'visualization',
                    'id': 'security-accuracy-viz'
                },
                {
                    'name': 'panel_failed_logins',
                    'type': 'visualization',
                    'id': 'failed-logins-viz'
                },
                {
                    'name': 'panel_stepup_rate',
                    'type': 'visualization',
                    'id': 'stepup-rate-viz'
                },
                {
                    'name': 'panel_stride_alerts',
                    'type': 'visualization',
                    'id': 'stride-alerts-viz'
                },
                {
                    'name': 'panel_validation_mismatches',
                    'type': 'visualization',
                    'id': 'validation-mismatches-viz'
                },
                {
                    'name': 'panel_decision_latency',
                    'type': 'visualization',
                    'id': 'decision-latency-viz'
                },
                {
                    'name': 'panel_privacy_metrics',
                    'type': 'visualization',
                    'id': 'privacy-metrics-viz'
                }
            ]
        }

        return dashboard_config

    def setup_all_dashboards(self):
        """Setup all dashboards and visualizations"""

        logger.info("Setting up Kibana dashboards...")

        # Check Kibana connectivity
        try:
            response = requests.get(f"{self.kibana_url}/api/status")
            if response.status_code != 200:
                logger.error(f"Kibana is not accessible at {self.kibana_url}")
                return False
        except Exception as e:
            logger.error(f"Cannot connect to Kibana: {e}")
            return False

        # Create index patterns
        logger.info("Creating index patterns...")
        self.create_index_patterns()

        # Create visualizations
        logger.info("Creating visualizations...")
        visualizations = [
            ('security-accuracy-viz', self.create_security_accuracy_visualization()),
            ('failed-logins-viz', self.create_failed_login_timeline_visualization()),
            ('stepup-rate-viz', self.create_stepup_challenge_rate_visualization()),
            ('stride-alerts-viz', self.create_stride_alerts_visualization()),
            ('decision-latency-viz', self.create_decision_latency_visualization()),
            ('privacy-metrics-viz', self.create_privacy_metrics_visualization()),
            ('validation-mismatches-viz', self.create_validation_mismatches_visualization())
        ]

        for viz_id, viz_config in visualizations:
            viz_config['id'] = viz_id
            result = self._make_kibana_request('POST', 'saved_objects/visualization', viz_config)
            if result:
                logger.info(f"✅ Created visualization: {viz_id}")
                self.visualizations.append(result)
            else:
                logger.warning(f"Failed to create visualization: {viz_id}")

        # Create main dashboard
        logger.info("Creating main dashboard...")
        dashboard = self.create_main_dashboard()
        dashboard['id'] = 'main-framework-dashboard'

        result = self._make_kibana_request('POST', 'saved_objects/dashboard', dashboard)
        if result:
            logger.info("✅ Created main dashboard")
            self.dashboards.append(result)
        else:
            logger.warning("Failed to create main dashboard")

        logger.info("""
╔════════════════════════════════════════════════════════════════════╗
║                     DASHBOARD SETUP COMPLETE                        ║
╠════════════════════════════════════════════════════════════════════╣
║ Access Kibana at: http://localhost:5601                            ║
║                                                                     ║
║ Dashboards Created:                                                ║
║ • Multi-Source MFA Framework Analysis                              ║
║                                                                     ║
║ Visualizations:                                                    ║
║ • Security Accuracy Metrics (TPR, FPR, Precision, Recall, F1)     ║
║ • Failed Login Timeline                                            ║
║ • Step-up Challenge Rate Comparison                                ║
║ • STRIDE Alerts Distribution                                       ║
║ • Decision Latency under Network Conditions                        ║
║ • Privacy Safeguard Metrics                                        ║
║ • Context Signal Mismatches                                        ║
╚════════════════════════════════════════════════════════════════════╝
        """)

        return True

def main():
    """Main entry point"""
    setup = DashboardSetup()
    success = setup.setup_all_dashboards()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
