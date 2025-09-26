# Advanced Queries for Multi-Source MFA ZTA Framework Thesis Analysis

This document contains sophisticated queries and analysis techniques for extracting meaningful insights from your research data.

## 🎯 Core Thesis Metrics Queries

### Framework Performance Comparison Query
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "framework_type"}},
        {"exists": {"field": "tpr"}},
        {"exists": {"field": "fpr"}}
      ]
    }
  },
  "aggs": {
    "framework_comparison": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "avg_tpr": {"avg": {"field": "tpr"}},
        "avg_fpr": {"avg": {"field": "fpr"}},
        "avg_precision": {"avg": {"field": "precision"}},
        "avg_recall": {"avg": {"field": "recall"}},
        "avg_f1_score": {"avg": {"field": "f1_score"}},
        "avg_latency": {"avg": {"field": "avg_decision_latency_ms"}},
        "effectiveness_score": {
          "bucket_script": {
            "buckets_path": {
              "tpr": "avg_tpr",
              "fpr": "avg_fpr",
              "precision": "avg_precision"
            },
            "script": "params.tpr * params.precision - params.fpr"
          }
        }
      }
    }
  }
}
```

### Risk-Based Authentication Effectiveness
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"exists": {"field": "risk_score"}}
      ]
    }
  },
  "aggs": {
    "risk_buckets": {
      "range": {
        "field": "risk_score",
        "ranges": [
          {"key": "low", "from": 0, "to": 0.3},
          {"key": "medium", "from": 0.3, "to": 0.7},
          {"key": "high", "from": 0.7, "to": 1.0}
        ]
      },
      "aggs": {
        "decisions": {
          "terms": {"field": "decision.keyword"},
          "aggs": {
            "avg_processing_time": {"avg": {"field": "processing_time_ms"}},
            "success_rate": {
              "bucket_script": {
                "buckets_path": {"total": "_count"},
                "script": "params.total > 0 ? (params.total / params.total) * 100 : 0"
              }
            }
          }
        }
      }
    }
  }
}
```

### Multi-Source Signal Contribution Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "signals_used"}}
      ]
    }
  },
  "aggs": {
    "signal_effectiveness": {
      "terms": {"field": "signals_used.keyword", "size": 20},
      "aggs": {
        "avg_risk_score": {"avg": {"field": "risk_score"}},
        "decision_outcomes": {
          "terms": {"field": "decision.keyword"}
        },
        "accuracy_by_signal": {
          "filter": {"term": {"outcome": "success"}},
          "aggs": {
            "success_rate": {
              "bucket_script": {
                "buckets_path": {"successes": "_count", "total": "_parent>_count"},
                "script": "params.total > 0 ? (params.successes / params.total) * 100 : 0"
              }
            }
          }
        }
      }
    }
  }
}
```

## 📊 Statistical Analysis Queries

### Framework Performance Distribution
```json
{
  "query": {"match_all": {}},
  "aggs": {
    "framework_stats": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "latency_distribution": {
          "percentiles": {
            "field": "processing_time_ms",
            "percents": [25, 50, 75, 95, 99]
          }
        },
        "accuracy_stats": {
          "stats": {"field": "accuracy"}
        },
        "throughput_trend": {
          "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "1d"
          },
          "aggs": {
            "daily_throughput": {"value_count": {"field": "session_id.keyword"}}
          }
        }
      }
    }
  }
}
```

### Security Classification Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "predicted_threats"}},
        {"exists": {"field": "actual_threats"}}
      ]
    }
  },
  "aggs": {
    "classification_matrix": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "true_positives": {
          "filter": {
            "script": {
              "source": "doc['predicted_threats.keyword'].length > 0 && doc['actual_threats.keyword'].length > 0"
            }
          }
        },
        "false_positives": {
          "filter": {
            "bool": {
              "must": [
                {"script": {"source": "doc['predicted_threats.keyword'].length > 0"}},
                {"script": {"source": "doc['actual_threats.keyword'].length == 0"}}
              ]
            }
          }
        },
        "false_negatives": {
          "filter": {
            "bool": {
              "must": [
                {"script": {"source": "doc['predicted_threats.keyword'].length == 0"}},
                {"script": {"source": "doc['actual_threats.keyword'].length > 0"}}
              ]
            }
          }
        },
        "classification_accuracy": {"avg": {"field": "classification_accuracy"}}
      }
    }
  }
}
```

## 🔐 Security-Specific Analysis

### STRIDE Threat Pattern Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "stride"}}
      ]
    }
  },
  "aggs": {
    "stride_analysis": {
      "terms": {"field": "stride.keyword"},
      "aggs": {
        "severity_distribution": {
          "terms": {"field": "severity.keyword"}
        },
        "temporal_pattern": {
          "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "1h"
          }
        },
        "source_analysis": {
          "terms": {"field": "source.keyword"}
        },
        "avg_confidence": {"avg": {"field": "confidence_score"}}
      }
    },
    "threat_correlation": {
      "significant_terms": {
        "field": "stride.keyword",
        "background_filter": {"match_all": {}}
      }
    }
  }
}
```

### User Behavior Pattern Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "session_id"}}
      ]
    }
  },
  "aggs": {
    "user_patterns": {
      "terms": {"field": "session_id.keyword", "size": 100},
      "aggs": {
        "session_duration": {
          "bucket_script": {
            "buckets_path": {},
            "script": "Math.abs(params._interval)"
          }
        },
        "risk_progression": {
          "date_histogram": {
            "field": "@timestamp",
            "calendar_interval": "1h"
          },
          "aggs": {
            "avg_risk": {"avg": {"field": "risk_score"}},
            "decision_changes": {
              "terms": {"field": "decision.keyword"}
            }
          }
        },
        "mfa_challenges": {
          "filter": {"term": {"enforcement.keyword": "MFA_STEP_UP"}},
          "aggs": {
            "challenge_frequency": {"value_count": {"field": "enforcement.keyword"}}
          }
        }
      }
    }
  }
}
```

## 🚀 Performance Analysis Queries

### System Load and Response Time Correlation
```json
{
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "load_analysis": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "5m"
      },
      "aggs": {
        "avg_response_time": {"avg": {"field": "processing_time_ms"}},
        "request_count": {"value_count": {"field": "session_id.keyword"}},
        "cpu_utilization": {"avg": {"field": "cpu_utilization_pct"}},
        "memory_usage": {"avg": {"field": "memory_utilization_mb"}},
        "load_correlation": {
          "bucket_script": {
            "buckets_path": {
              "response": "avg_response_time",
              "requests": "request_count"
            },
            "script": "params.response * Math.log(params.requests + 1)"
          }
        }
      }
    }
  }
}
```

### Scalability Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"exists": {"field": "throughput_rps"}}
      ]
    }
  },
  "aggs": {
    "scalability_metrics": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "throughput_analysis": {
          "range": {
            "field": "throughput_rps",
            "ranges": [
              {"key": "low_load", "to": 100},
              {"key": "medium_load", "from": 100, "to": 500},
              {"key": "high_load", "from": 500}
            ]
          },
          "aggs": {
            "avg_latency": {"avg": {"field": "avg_decision_latency_ms"}},
            "p95_latency": {"percentiles": {"field": "avg_decision_latency_ms", "percents": [95]}},
            "success_rate": {
              "bucket_script": {
                "buckets_path": {"total": "_count"},
                "script": "params.total"
              }
            }
          }
        }
      }
    }
  }
}
```

## 💡 Business Impact Analysis

### Cost-Benefit Analysis Query
```json
{
  "query": {
    "range": {"@timestamp": {"gte": "now-30d"}}
  },
  "aggs": {
    "cost_benefit": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "resource_cost": {
          "sum": {
            "script": {
              "source": "(doc['cpu_utilization_pct'].value * 0.001) + (doc['memory_utilization_mb'].value * 0.0001)"
            }
          }
        },
        "security_benefit": {
          "sum": {
            "script": {
              "source": "doc['tpr'].value * 100 - doc['fpr'].value * 10"
            }
          }
        },
        "user_satisfaction": {
          "bucket_script": {
            "buckets_path": {
              "continuity": "avg_continuity",
              "friction": "avg_friction"
            },
            "script": "(params.continuity / 100) * (1 - params.friction / 100) * 100"
          }
        },
        "avg_continuity": {"avg": {"field": "session_continuity_pct"}},
        "avg_friction": {"avg": {"field": "user_friction_index"}}
      }
    }
  }
}
```

### Privacy Compliance Analysis
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "data_minimization_compliance_pct"}},
        {"exists": {"field": "privacy_leakage_rate_pct"}}
      ]
    }
  },
  "aggs": {
    "privacy_metrics": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "compliance_score": {
          "bucket_script": {
            "buckets_path": {
              "minimization": "avg_minimization",
              "leakage": "avg_leakage"
            },
            "script": "params.minimization - params.leakage"
          }
        },
        "avg_minimization": {"avg": {"field": "data_minimization_compliance_pct"}},
        "avg_leakage": {"avg": {"field": "privacy_leakage_rate_pct"}},
        "privacy_violations": {
          "filter": {"range": {"privacy_leakage_rate_pct": {"gt": 5}}}
        }
      }
    }
  }
}
```

## 📈 Time Series Analysis

### Trend Analysis with Seasonal Decomposition
```json
{
  "query": {
    "range": {"@timestamp": {"gte": "now-90d"}}
  },
  "aggs": {
    "trend_analysis": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1d"
      },
      "aggs": {
        "daily_metrics": {
          "terms": {"field": "framework_type.keyword"},
          "aggs": {
            "avg_accuracy": {"avg": {"field": "accuracy"}},
            "avg_latency": {"avg": {"field": "processing_time_ms"}},
            "threat_count": {
              "filter": {"range": {"risk_score": {"gte": 0.7}}}
            }
          }
        },
        "trend_derivative": {
          "derivative": {
            "buckets_path": "daily_metrics>avg_accuracy"
          }
        }
      }
    }
  }
}
```

## 🔍 Anomaly Detection Queries

### Statistical Anomaly Detection
```json
{
  "query": {
    "range": {"@timestamp": {"gte": "now-24h"}}
  },
  "aggs": {
    "anomaly_detection": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      },
      "aggs": {
        "response_time_stats": {
          "extended_stats": {"field": "processing_time_ms"}
        },
        "anomaly_score": {
          "bucket_script": {
            "buckets_path": {
              "avg": "response_time_stats.avg",
              "std": "response_time_stats.std_deviation"
            },
            "script": "Math.abs(params.avg - params.std) > (params.std * 2) ? 1 : 0"
          }
        }
      }
    }
  }
}
```

## 📋 Thesis Defense Presentation Queries

### Executive Summary Statistics
```json
{
  "query": {"match_all": {}},
  "aggs": {
    "thesis_summary": {
      "global": {},
      "aggs": {
        "total_authentications": {"value_count": {"field": "session_id.keyword"}},
        "frameworks_tested": {"cardinality": {"field": "framework_type.keyword"}},
        "avg_improvement": {
          "terms": {"field": "framework_type.keyword"},
          "aggs": {
            "performance_score": {
              "bucket_script": {
                "buckets_path": {
                  "tpr": "avg_tpr",
                  "precision": "avg_precision",
                  "latency": "avg_latency"
                },
                "script": "(params.tpr * params.precision) / (params.latency / 1000)"
              }
            },
            "avg_tpr": {"avg": {"field": "tpr"}},
            "avg_precision": {"avg": {"field": "precision"}},
            "avg_latency": {"avg": {"field": "processing_time_ms"}}
          }
        }
      }
    }
  }
}
```

### Research Contribution Metrics
```json
{
  "query": {
    "range": {"@timestamp": {"gte": "now-90d"}}
  },
  "aggs": {
    "research_impact": {
      "terms": {"field": "framework_type.keyword"},
      "aggs": {
        "security_improvement": {
          "bucket_script": {
            "buckets_path": {
              "current_tpr": "current_metrics.avg_tpr",
              "baseline_tpr": "baseline_metrics.avg_tpr"
            },
            "script": "((params.current_tpr - params.baseline_tpr) / params.baseline_tpr) * 100"
          }
        },
        "current_metrics": {
          "filter": {"term": {"metric_type.keyword": "current"}},
          "aggs": {
            "avg_tpr": {"avg": {"field": "tpr"}}
          }
        },
        "baseline_metrics": {
          "filter": {"term": {"metric_type.keyword": "baseline"}},
          "aggs": {
            "avg_tpr": {"avg": {"field": "tpr"}}
          }
        }
      }
    }
  }
}
```

## 📊 Export Queries for Statistical Analysis

Use these queries in Kibana's Dev Tools, then export results for analysis in R, Python, or Excel:

### Data Export for Statistical Testing
```json
{
  "_source": [
    "@timestamp",
    "framework_type",
    "tpr",
    "fpr",
    "precision",
    "recall",
    "f1_score",
    "processing_time_ms",
    "risk_score",
    "decision",
    "session_continuity_pct",
    "user_friction_index"
  ],
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-30d"}}},
        {"exists": {"field": "framework_type"}}
      ]
    }
  },
  "size": 10000,
  "sort": [{"@timestamp": {"order": "desc"}}]
}
```

These queries provide comprehensive analysis capabilities for your Multi-Source MFA ZTA Framework thesis, covering performance comparison, security analysis, user experience metrics, and statistical validation of your research findings.