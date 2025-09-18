#!/usr/bin/env python3
"""
Kibana Dashboard Creation Script
Creates dashboards, visualizations, and index patterns for Multi-Source MFA ZTA Framework

Usage:
    python create_kibana_dashboards.py --kibana-url http://localhost:5601
    python create_kibana_dashboards.py --export-configs
    python create_kibana_dashboards.py --create-all
"""

import os
import json
import asyncio
import argparse
from typing import Dict, Any, List
import httpx
from pathlib import Path
from datetime import datetime

# Kibana configuration
KIBANA_DEFAULT_URL = "http://localhost:5601"
ELASTICSEARCH_URL = "http://localhost:9200"

# Dashboard configurations
DASHBOARD_CONFIGS = {
    "mfa_framework_overview": {
        "title": "Multi-Source MFA Framework Overview",
        "description": "Comprehensive view of authentication decisions and security events",
        "index_pattern": "mfa-events-*",
        "visualizations": [
            "decision_distribution_pie",
            "risk_score_histogram",
            "timeline_events",
            "framework_comparison_bar"
        ]
    },
    "security_effectiveness": {
        "title": "Security Effectiveness Dashboard",
        "description": "Attack detection and threat analysis dashboard",
        "index_pattern": "siem-alerts-*",
        "visualizations": [
            "stride_category_breakdown",
            "severity_distribution",
            "attack_timeline",
            "false_positive_analysis"
        ]
    },
    "performance_monitoring": {
        "title": "System Performance Monitoring",
        "description": "Real-time system performance and health metrics",
        "index_pattern": "validated-context-*",
        "visualizations": [
            "response_time_trends",
            "service_health_status",
            "throughput_metrics",
            "error_rate_gauge"
        ]
    },
    "thesis_comparison": {
        "title": "Thesis Framework Comparison",
        "description": "Side-by-side comparison of Proposed vs Baseline frameworks",
        "index_pattern": "mfa-events-*",
        "visualizations": [
            "framework_performance_table",
            "decision_accuracy_comparison",
            "processing_time_comparison",
            "threat_detection_effectiveness"
        ]
    }
}

# Index pattern configurations
INDEX_PATTERNS = {
    "mfa-events-*": {
        "title": "mfa-events-*",
        "timeFieldName": "@timestamp",
        "fields": {
            "@timestamp": {"type": "date"},
            "session_id": {"type": "keyword"},
            "decision": {"type": "keyword"},
            "risk_score": {"type": "float"},
            "enforcement": {"type": "keyword"},
            "reasons": {"type": "keyword"},
            "stride_category": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "framework_type": {"type": "keyword"}
        }
    },
    "siem-alerts-*": {
        "title": "siem-alerts-*",
        "timeFieldName": "@timestamp",
        "fields": {
            "@timestamp": {"type": "date"},
            "session_id": {"type": "keyword"},
            "stride": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "source": {"type": "keyword"}
        }
    },
    "validated-context-*": {
        "title": "validated-context-*",
        "timeFieldName": "@timestamp",
        "fields": {
            "@timestamp": {"type": "date"},
            "session_id": {"type": "keyword"},
            "signals": {"type": "object"},
            "validated": {"type": "object"},
            "quality": {"type": "object"}
        }
    }
}

# Visualization configurations
VISUALIZATIONS = {
    "decision_distribution_pie": {
        "title": "Authentication Decision Distribution",
        "type": "pie",
        "index_pattern": "mfa-events-*",
        "config": {
            "buckets": [
                {
                    "type": "terms",
                    "field": "decision",
                    "size": 10
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    },
    "risk_score_histogram": {
        "title": "Risk Score Distribution",
        "type": "histogram",
        "index_pattern": "mfa-events-*",
        "config": {
            "buckets": [
                {
                    "type": "histogram",
                    "field": "risk_score",
                    "interval": 0.1
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    },
    "timeline_events": {
        "title": "Authentication Events Timeline",
        "type": "line",
        "index_pattern": "mfa-events-*",
        "config": {
            "buckets": [
                {
                    "type": "date_histogram",
                    "field": "@timestamp",
                    "interval": "auto"
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    },
    "framework_comparison_bar": {
        "title": "Framework Performance Comparison",
        "type": "horizontal_bar",
        "index_pattern": "mfa-events-*",
        "config": {
            "buckets": [
                {
                    "type": "terms",
                    "field": "framework_type",
                    "size": 10
                },
                {
                    "type": "terms",
                    "field": "decision",
                    "size": 10
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    },
    "stride_category_breakdown": {
        "title": "STRIDE Threat Category Breakdown",
        "type": "pie",
        "index_pattern": "siem-alerts-*",
        "config": {
            "buckets": [
                {
                    "type": "terms",
                    "field": "stride",
                    "size": 6
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    },
    "severity_distribution": {
        "title": "Alert Severity Distribution",
        "type": "vertical_bar",
        "index_pattern": "siem-alerts-*",
        "config": {
            "buckets": [
                {
                    "type": "terms",
                    "field": "severity",
                    "order": {
                        "_key": "desc"
                    }
                }
            ],
            "metrics": [
                {
                    "type": "count"
                }
            ]
        }
    }
}

class KibanaDashboardCreator:
    def __init__(self, kibana_url: str = KIBANA_DEFAULT_URL, elasticsearch_url: str = ELASTICSEARCH_URL):
        self.kibana_url = kibana_url.rstrip('/')
        self.elasticsearch_url = elasticsearch_url.rstrip('/')
        self.session = None

    async def __aenter__(self):
        self.session = httpx.AsyncClient(timeout=30.0)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()

    async def check_kibana_health(self) -> bool:
        """Check if Kibana is accessible"""
        try:
            response = await self.session.get(f"{self.kibana_url}/api/status")
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Kibana health check failed: {e}")
            return False

    async def check_elasticsearch_health(self) -> bool:
        """Check if Elasticsearch is accessible"""
        try:
            response = await self.session.get(f"{self.elasticsearch_url}/_cluster/health")
            return response.status_code == 200
        except Exception as e:
            print(f"❌ Elasticsearch health check failed: {e}")
            return False

    async def create_index_pattern(self, pattern_id: str, config: Dict[str, Any]) -> bool:
        """Create an index pattern in Kibana"""
        print(f"🔍 Creating index pattern: {pattern_id}")

        try:
            payload = {
                "attributes": {
                    "title": config["title"],
                    "timeFieldName": config.get("timeFieldName", "@timestamp"),
                    "fields": json.dumps([
                        {
                            "name": field_name,
                            "type": field_config["type"],
                            "searchable": True,
                            "aggregatable": field_config["type"] in ["keyword", "long", "float", "double"]
                        }
                        for field_name, field_config in config.get("fields", {}).items()
                    ])
                }
            }

            headers = {
                "Content-Type": "application/json",
                "kbn-xsrf": "true"
            }

            response = await self.session.post(
                f"{self.kibana_url}/api/saved_objects/index-pattern/{pattern_id}",
                headers=headers,
                json=payload
            )

            if response.status_code in [200, 201]:
                print(f"  ✅ Index pattern '{pattern_id}' created successfully")
                return True
            else:
                print(f"  ⚠️ Index pattern creation returned {response.status_code}: {response.text}")
                return False

        except Exception as e:
            print(f"  ❌ Error creating index pattern '{pattern_id}': {e}")
            return False

    async def create_visualization(self, viz_id: str, config: Dict[str, Any]) -> bool:
        """Create a visualization in Kibana"""
        print(f"📊 Creating visualization: {viz_id}")

        try:
            # Simplified visualization payload (actual implementation would be more complex)
            payload = {
                "attributes": {
                    "title": config["title"],
                    "visState": json.dumps({
                        "type": config["type"],
                        "params": {
                            "addTooltip": True,
                            "addLegend": True,
                            "isDonut": config["type"] == "pie"
                        },
                        "aggs": []  # Aggregation configuration would go here
                    }),
                    "uiStateJSON": "{}",
                    "description": "",
                    "version": 1,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "index": config["index_pattern"],
                            "query": {
                                "match_all": {}
                            },
                            "filter": []
                        })
                    }
                }
            }

            headers = {
                "Content-Type": "application/json",
                "kbn-xsrf": "true"
            }

            response = await self.session.post(
                f"{self.kibana_url}/api/saved_objects/visualization/{viz_id}",
                headers=headers,
                json=payload
            )

            if response.status_code in [200, 201]:
                print(f"  ✅ Visualization '{viz_id}' created successfully")
                return True
            else:
                print(f"  ⚠️ Visualization creation returned {response.status_code}: {response.text}")
                return False

        except Exception as e:
            print(f"  ❌ Error creating visualization '{viz_id}': {e}")
            return False

    async def create_dashboard(self, dashboard_id: str, config: Dict[str, Any]) -> bool:
        """Create a dashboard in Kibana"""
        print(f"📋 Creating dashboard: {dashboard_id}")

        try:
            # Create panels for each visualization
            panels = []
            for i, viz_id in enumerate(config.get("visualizations", [])):
                panels.append({
                    "gridData": {
                        "x": (i % 2) * 24,
                        "y": (i // 2) * 15,
                        "w": 24,
                        "h": 15,
                        "i": str(i + 1)
                    },
                    "panelIndex": str(i + 1),
                    "embeddableConfig": {},
                    "panelRefName": f"panel_{i + 1}"
                })

            payload = {
                "attributes": {
                    "title": config["title"],
                    "description": config.get("description", ""),
                    "panelsJSON": json.dumps(panels),
                    "optionsJSON": json.dumps({
                        "darkTheme": False,
                        "hidePanelTitles": False,
                        "useMargins": True
                    }),
                    "version": 1,
                    "kibanaSavedObjectMeta": {
                        "searchSourceJSON": json.dumps({
                            "query": {
                                "match_all": {}
                            },
                            "filter": []
                        })
                    }
                },
                "references": [
                    {
                        "name": f"panel_{i + 1}",
                        "type": "visualization",
                        "id": viz_id
                    }
                    for i, viz_id in enumerate(config.get("visualizations", []))
                ]
            }

            headers = {
                "Content-Type": "application/json",
                "kbn-xsrf": "true"
            }

            response = await self.session.post(
                f"{self.kibana_url}/api/saved_objects/dashboard/{dashboard_id}",
                headers=headers,
                json=payload
            )

            if response.status_code in [200, 201]:
                print(f"  ✅ Dashboard '{dashboard_id}' created successfully")
                return True
            else:
                print(f"  ⚠️ Dashboard creation returned {response.status_code}: {response.text}")
                return False

        except Exception as e:
            print(f"  ❌ Error creating dashboard '{dashboard_id}': {e}")
            return False

    async def export_dashboard_config(self, dashboard_id: str) -> Dict[str, Any]:
        """Export dashboard configuration"""
        try:
            response = await self.session.get(
                f"{self.kibana_url}/api/saved_objects/dashboard/{dashboard_id}"
            )

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"Dashboard not found or inaccessible: {response.status_code}"}

        except Exception as e:
            return {"error": str(e)}

    def generate_manual_instructions(self, output_dir: Path):
        """Generate manual dashboard creation instructions"""
        print("📖 Generating manual dashboard creation instructions...")

        instructions = """# Manual Kibana Dashboard Creation Guide

This guide provides step-by-step instructions for manually creating dashboards for the Multi-Source MFA ZTA Framework.

## Prerequisites

1. Kibana running on http://localhost:5601
2. Elasticsearch running with data indexes:
   - `mfa-events-*`
   - `siem-alerts-*`
   - `validated-context-*`

## Step 1: Create Index Patterns

### 1.1 MFA Events Index Pattern
1. Go to Kibana → Stack Management → Index Patterns
2. Click "Create index pattern"
3. Index pattern name: `mfa-events-*`
4. Time field: `@timestamp`
5. Click "Create index pattern"

### 1.2 SIEM Alerts Index Pattern
1. Click "Create index pattern"
2. Index pattern name: `siem-alerts-*`
3. Time field: `@timestamp`
4. Click "Create index pattern"

### 1.3 Validated Context Index Pattern
1. Click "Create index pattern"
2. Index pattern name: `validated-context-*`
3. Time field: `@timestamp`
4. Click "Create index pattern"

## Step 2: Create Visualizations

### 2.1 Authentication Decision Distribution (Pie Chart)
1. Go to Kibana → Visualize → Create visualization
2. Select "Pie chart"
3. Choose index pattern: `mfa-events-*`
4. Buckets → Add → Terms
   - Field: `decision`
   - Size: 10
5. Apply changes
6. Save as "Authentication Decision Distribution"

### 2.2 Risk Score Distribution (Histogram)
1. Create visualization → Histogram
2. Choose index pattern: `mfa-events-*`
3. X-axis → Add → Histogram
   - Field: `risk_score`
   - Interval: 0.1
4. Save as "Risk Score Distribution"

### 2.3 Framework Performance Comparison (Bar Chart)
1. Create visualization → Horizontal Bar Chart
2. Choose index pattern: `mfa-events-*`
3. Y-axis → Add → Terms
   - Field: `framework_type`
4. Split series → Add → Terms
   - Field: `decision`
5. Save as "Framework Performance Comparison"

### 2.4 STRIDE Threat Breakdown (Pie Chart)
1. Create visualization → Pie Chart
2. Choose index pattern: `siem-alerts-*`
3. Buckets → Add → Terms
   - Field: `stride`
   - Size: 6
4. Save as "STRIDE Threat Breakdown"

### 2.5 Alert Severity Distribution (Bar Chart)
1. Create visualization → Vertical Bar Chart
2. Choose index pattern: `siem-alerts-*`
3. X-axis → Add → Terms
   - Field: `severity`
   - Order: Descending
4. Save as "Alert Severity Distribution"

### 2.6 Events Timeline (Line Chart)
1. Create visualization → Line Chart
2. Choose index pattern: `mfa-events-*`
3. X-axis → Add → Date Histogram
   - Field: `@timestamp`
   - Interval: Auto
4. Save as "Events Timeline"

## Step 3: Create Dashboards

### 3.1 Multi-Source MFA Framework Overview
1. Go to Kibana → Dashboard → Create dashboard
2. Add visualizations:
   - Authentication Decision Distribution
   - Risk Score Distribution
   - Framework Performance Comparison
   - Events Timeline
3. Arrange panels in a 2x2 grid
4. Save as "Multi-Source MFA Framework Overview"

### 3.2 Security Effectiveness Dashboard
1. Create dashboard
2. Add visualizations:
   - STRIDE Threat Breakdown
   - Alert Severity Distribution
   - Events Timeline (filtered for security events)
3. Save as "Security Effectiveness Dashboard"

### 3.3 Thesis Comparison Dashboard
1. Create dashboard
2. Add visualizations:
   - Framework Performance Comparison
   - Decision Distribution (split by framework_type)
   - Risk Score Distribution (split by framework_type)
3. Add filters:
   - framework_type: proposed OR baseline
4. Save as "Thesis Framework Comparison"

## Step 4: Configure Time Ranges and Filters

### Global Time Range
- Set to "Last 7 days" for comprehensive analysis
- Use "Last 24 hours" for real-time monitoring

### Useful Filters
- `framework_type: "proposed"` - Show only proposed framework data
- `framework_type: "baseline"` - Show only baseline framework data
- `decision: "deny"` - Show only blocked authentication attempts
- `severity: "high"` - Show only high-severity security alerts
- `stride: "Spoofing"` - Show specific STRIDE category threats

## Step 5: Export and Share

### Export Dashboard
1. Go to dashboard
2. Click Share → Export
3. Choose format (PDF, PNG, etc.)

### Share Dashboard
1. Click Share → Get links
2. Copy permalink for sharing
3. Use embed code for external integration

## Dashboard URLs (after creation)

- Framework Overview: http://localhost:5601/app/dashboards#/view/mfa_framework_overview
- Security Effectiveness: http://localhost:5601/app/dashboards#/view/security_effectiveness
- Thesis Comparison: http://localhost:5601/app/dashboards#/view/thesis_comparison

## Troubleshooting

### No Data Showing
1. Check if Elasticsearch indices exist: `GET /_cat/indices`
2. Verify time range matches your data
3. Check index pattern field mappings

### Visualization Errors
1. Refresh index patterns: Stack Management → Index Patterns → Refresh
2. Check field types and mappings
3. Verify aggregation settings

### Performance Issues
1. Reduce time range
2. Add more specific filters
3. Limit aggregation bucket sizes

## Custom Queries for Advanced Analysis

### Framework Comparison Query
```json
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"terms": {"framework_type": ["proposed", "baseline"]}}
      ]
    }
  },
  "aggs": {
    "by_framework": {
      "terms": {"field": "framework_type"},
      "aggs": {
        "decisions": {"terms": {"field": "decision"}},
        "avg_risk": {"avg": {"field": "risk_score"}}
      }
    }
  }
}
```

### Security Effectiveness Query
```json
{
  "query": {
    "bool": {
      "filter": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"exists": {"field": "stride"}}
      ]
    }
  },
  "aggs": {
    "stride_breakdown": {
      "terms": {"field": "stride"},
      "aggs": {
        "severity_dist": {"terms": {"field": "severity"}}
      }
    }
  }
}
```

---

*This guide was generated for the Multi-Source MFA ZTA Framework thesis project.*
*For automated dashboard creation, use the `create_kibana_dashboards.py` script.*
"""

        with open(output_dir / "KIBANA_MANUAL_SETUP.md", "w") as f:
            f.write(instructions)

        print(f"✅ Manual instructions saved to {output_dir / 'KIBANA_MANUAL_SETUP.md'}")

    def save_dashboard_configs(self, output_dir: Path):
        """Save dashboard configurations as JSON files"""
        print("💾 Saving dashboard configurations...")

        config_dir = output_dir / "dashboard_configs"
        config_dir.mkdir(exist_ok=True)

        # Save all configurations
        all_configs = {
            "index_patterns": INDEX_PATTERNS,
            "visualizations": VISUALIZATIONS,
            "dashboards": DASHBOARD_CONFIGS,
            "metadata": {
                "created": datetime.now().isoformat(),
                "version": "1.0",
                "kibana_version": "8.x",
                "description": "Multi-Source MFA ZTA Framework Dashboard Configurations"
            }
        }

        with open(config_dir / "complete_dashboard_config.json", "w") as f:
            json.dump(all_configs, f, indent=2)

        # Save individual configuration files
        for config_type, configs in all_configs.items():
            if config_type != "metadata":
                with open(config_dir / f"{config_type}.json", "w") as f:
                    json.dump(configs, f, indent=2)

        print(f"✅ Dashboard configurations saved to {config_dir}")

    async def create_all_objects(self) -> bool:
        """Create all index patterns, visualizations, and dashboards"""
        print("🚀 Creating all Kibana objects...")

        success = True

        # Check system health
        kibana_ok = await self.check_kibana_health()
        es_ok = await self.check_elasticsearch_health()

        if not kibana_ok or not es_ok:
            print("❌ System health check failed. Cannot proceed.")
            return False

        # Create index patterns
        print("\n📍 Creating index patterns...")
        for pattern_id, config in INDEX_PATTERNS.items():
            result = await self.create_index_pattern(pattern_id, config)
            success = success and result

        # Create visualizations
        print("\n📊 Creating visualizations...")
        for viz_id, config in VISUALIZATIONS.items():
            result = await self.create_visualization(viz_id, config)
            success = success and result

        # Create dashboards
        print("\n📋 Creating dashboards...")
        for dashboard_id, config in DASHBOARD_CONFIGS.items():
            result = await self.create_dashboard(dashboard_id, config)
            success = success and result

        return success

async def main():
    parser = argparse.ArgumentParser(description="Create Kibana dashboards for Multi-Source MFA ZTA Framework")
    parser.add_argument("--kibana-url", default=KIBANA_DEFAULT_URL, help="Kibana URL")
    parser.add_argument("--elasticsearch-url", default=ELASTICSEARCH_URL, help="Elasticsearch URL")
    parser.add_argument("--create-all", action="store_true", help="Create all dashboards and visualizations")
    parser.add_argument("--export-configs", action="store_true", help="Export dashboard configurations only")
    parser.add_argument("--manual-instructions", action="store_true", help="Generate manual setup instructions")
    parser.add_argument("--output", default="kibana_setup", help="Output directory")

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    print("🎛️  Kibana Dashboard Creation Tool")
    print(f"📡 Kibana URL: {args.kibana_url}")
    print(f"🔍 Elasticsearch URL: {args.elasticsearch_url}")
    print(f"📁 Output directory: {output_dir}")
    print()

    async with KibanaDashboardCreator(args.kibana_url, args.elasticsearch_url) as creator:

        if args.export_configs or not any([args.create_all, args.manual_instructions]):
            creator.save_dashboard_configs(output_dir)

        if args.manual_instructions or not any([args.create_all, args.export_configs]):
            creator.generate_manual_instructions(output_dir)

        if args.create_all:
            print("🚀 Attempting to create all Kibana objects...")
            success = await creator.create_all_objects()

            if success:
                print("\n✅ All Kibana objects created successfully!")
                print(f"🌐 Access dashboards at: {args.kibana_url}/app/dashboards")
            else:
                print("\n⚠️  Some objects failed to create. Check logs above.")
                print("💡 Try manual creation using the generated instructions.")

    print(f"\n📋 Setup files saved to: {output_dir}")
    print("🎓 Use these dashboards for thesis data visualization and analysis!")

if __name__ == "__main__":
    asyncio.run(main())
