# Kibana Dashboard Setup Guide for Multi-Source MFA ZTA Framework

This guide provides step-by-step instructions for creating comprehensive dashboards to visualize your thesis research data.

## 📋 Prerequisites

- Kibana running on http://localhost:5601
- Data views configured for:
  - `baseline-decisions`
  - `framework-comparison-2025-09-26`
  - `mfa-events`
  - `security-classifications-2025-09-26`
  - `siem-alerts`
  - `validated-context`

## 🎯 Dashboard Strategy Overview

### 1. Executive Overview Dashboard
**Purpose**: High-level KPIs for stakeholders and thesis defense
**Audience**: Supervisors, external reviewers, management

### 2. Framework Comparison Dashboard
**Purpose**: Core thesis research - comparative analysis
**Audience**: Technical reviewers, peer researchers

### 3. Security Operations Dashboard
**Purpose**: Real-time security monitoring and threat analysis
**Audience**: Security analysts, technical audience

### 4. Performance & Reliability Dashboard
**Purpose**: System performance and technical metrics
**Audience**: Engineers, technical reviewers

## 🚀 Step-by-Step Dashboard Creation

### Dashboard 1: Executive Overview

1. **Navigate to Kibana** → **Dashboard** → **Create dashboard**

2. **Add Key Metrics Panel**
   ```
   Visualization Type: Metric
   Data View: mfa-events
   Metric: Count of documents
   Time Range: Last 24 hours
   Title: "Total Authentication Events (24h)"
   ```

3. **Add Security Posture Gauge**
   ```
   Visualization Type: Gauge
   Data View: siem-alerts
   Metric: Average of severity (convert: low=1, medium=2, high=3)
   Ranges: 1-1.5 (Good), 1.5-2.5 (Moderate), 2.5-3 (Poor)
   Title: "Security Posture Score"
   ```

4. **Add Risk Distribution Pie Chart**
   ```
   Visualization Type: Pie
   Data View: framework-comparison-2025-09-26
   Buckets: Split slices by risk_score ranges
   - Low: 0-0.3
   - Medium: 0.3-0.7
   - High: 0.7-1.0
   Title: "Risk Score Distribution"
   ```

5. **Add Framework Performance Comparison**
   ```
   Visualization Type: Horizontal Bar
   Data View: framework-comparison-2025-09-26
   X-axis: Average of processing_time_ms
   Y-axis: Terms aggregation on framework_type
   Title: "Average Processing Time by Framework"
   ```

6. **Add Threat Timeline**
   ```
   Visualization Type: Area
   Data View: siem-alerts
   X-axis: Date histogram on @timestamp (1 hour interval)
   Y-axis: Count
   Split series: Terms on severity
   Title: "Threat Detection Timeline"
   ```

### Dashboard 2: Framework Comparison (Core Thesis)

1. **Create New Dashboard** → "Framework Comparison Analysis"

2. **Add Performance Metrics Comparison**
   ```
   Visualization Type: Line
   Data View: thesis-metrics (from Elasticsearch indexer)
   X-axis: Date histogram on @timestamp
   Y-axis: Multiple metrics:
   - Average TPR
   - Average FPR
   - Average Precision
   - Average Recall
   - Average F1-Score
   Split series: Terms on framework_type
   Title: "Framework Performance Metrics Over Time"
   ```

3. **Add Decision Latency Box Plot**
   ```
   Visualization Type: Horizontal Bar (with percentiles)
   Data View: framework-comparison-2025-09-26
   X-axis: Percentiles of processing_time_ms (50th, 95th, 99th)
   Y-axis: Terms on framework_type
   Title: "Decision Latency Distribution by Framework"
   ```

4. **Add Success Rate vs Risk Scatter Plot**
   ```
   Visualization Type: Line (as scatter)
   Data View: framework-comparison-2025-09-26
   X-axis: Range of risk_score (buckets: 0-0.1, 0.1-0.2, etc.)
   Y-axis: Percentage of successful authentications
   Split series: Terms on framework_type
   Title: "Success Rate vs Risk Score by Framework"
   ```

5. **Add Decision Distribution**
   ```
   Visualization Type: Stacked Bar
   Data View: framework-comparison-2025-09-26
   X-axis: Terms on framework_type
   Y-axis: Count
   Split series: Terms on decision (Allow/MFA/Deny)
   Title: "Decision Distribution by Framework"
   ```

6. **Add Resource Utilization**
   ```
   Visualization Type: Area (stacked)
   Data View: thesis-metrics
   X-axis: Date histogram on @timestamp
   Y-axis: Metrics:
   - Average cpu_utilization_pct
   - Average memory_utilization_mb (normalized)
   Split series: Terms on framework
   Title: "Resource Utilization Comparison"
   ```

### Dashboard 3: Security Operations

1. **Create New Dashboard** → "Security Operations Center"

2. **Add SIEM Alert Heatmap**
   ```
   Visualization Type: Heat Map
   Data View: siem-alerts
   X-axis: Date histogram on @timestamp (1 hour)
   Y-axis: Terms on stride
   Values: Count
   Title: "STRIDE Threat Pattern Heatmap"
   ```

3. **Add Alert Severity Timeline**
   ```
   Visualization Type: Area (stacked)
   Data View: siem-alerts
   X-axis: Date histogram on @timestamp (15 min intervals)
   Y-axis: Count
   Split series: Terms on severity
   Colors: Green (low), Yellow (medium), Red (high)
   Title: "Security Alert Timeline by Severity"
   ```

4. **Add Top Risk Sessions Table**
   ```
   Visualization Type: Data Table
   Data View: framework-comparison-2025-09-26
   Columns:
   - session_id
   - risk_score (highest values)
   - decision
   - enforcement
   - @timestamp
   Sort: risk_score descending
   Size: Top 10
   Title: "Highest Risk Sessions"
   ```

5. **Add Security Classifications Accuracy**
   ```
   Visualization Type: Gauge
   Data View: security-classifications-2025-09-26
   Metric: Average of classification_accuracy
   Ranges: 0-0.7 (Poor), 0.7-0.85 (Good), 0.85-1.0 (Excellent)
   Title: "Classification Accuracy"
   ```

6. **Add False Positive/Negative Rates**
   ```
   Visualization Type: Metric (dual)
   Data View: security-classifications-2025-09-26
   Metrics:
   - Percentage where false_positive = true
   - Percentage where false_negative = true
   Title: "False Positive & Negative Rates"
   ```

### Dashboard 4: Performance & Reliability

1. **Create New Dashboard** → "System Performance"

2. **Add Response Time Percentiles**
   ```
   Visualization Type: Line
   Data View: framework-comparison-2025-09-26
   X-axis: Date histogram on @timestamp
   Y-axis: Percentiles of processing_time_ms (50, 95, 99)
   Title: "Response Time Percentiles"
   ```

3. **Add Throughput Rate**
   ```
   Visualization Type: Area
   Data View: mfa-events
   X-axis: Date histogram on @timestamp (1 minute intervals)
   Y-axis: Count per minute (derivative)
   Title: "Authentication Throughput (Events/min)"
   ```

4. **Add Error Rate**
   ```
   Visualization Type: Line
   Data View: mfa-events
   X-axis: Date histogram on @timestamp
   Y-axis: Percentage of events where outcome != "success"
   Title: "Authentication Error Rate"
   ```

5. **Add System Health Status**
   ```
   Visualization Type: Metric (multi-panel)
   Data View: Multiple sources
   Metrics:
   - Active sessions count
   - Average system response time
   - Success rate percentage
   - Alert count (last hour)
   Title: "System Health Dashboard"
   ```

## 🎨 Dashboard Styling Best Practices

### Color Schemes
- **Success/Safe**: Green (#00CC88)
- **Warning/Medium Risk**: Yellow/Orange (#FFCC00)
- **Error/High Risk**: Red (#FF6B6B)
- **Framework A**: Blue (#4A90E2)
- **Framework B**: Purple (#7B68EE)
- **Framework C**: Teal (#17A2B8)

### Layout Guidelines
1. **Executive Dashboard**: 2x3 grid, large metrics at top
2. **Technical Dashboards**: 3x4 grid, detailed charts
3. **Time Range**: Set default to "Last 24 hours" for real-time, "Last 7 days" for trends
4. **Refresh Rate**: 30 seconds for operational dashboards, 5 minutes for analytical

## 📊 Advanced Visualizations

### Custom Queries for Thesis Metrics

**Framework Effectiveness Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-7d"}}},
        {"exists": {"field": "tpr"}},
        {"exists": {"field": "fpr"}}
      ]
    }
  },
  "aggs": {
    "frameworks": {
      "terms": {"field": "framework.keyword"},
      "aggs": {
        "effectiveness": {
          "script": {
            "source": "params.tpr - params.fpr",
            "params": {
              "tpr": {"avg": {"field": "tpr"}},
              "fpr": {"avg": {"field": "fpr"}}
            }
          }
        }
      }
    }
  }
}
```

**User Experience Score Query**:
```json
{
  "aggs": {
    "ux_score": {
      "script": {
        "source": "(params.continuity * 0.4) + (params.friction * 0.3) + (params.success * 0.3)",
        "params": {
          "continuity": {"avg": {"field": "session_continuity_pct"}},
          "friction": {"avg": {"script": "100 - doc['user_friction_index'].value"}},
          "success": {"avg": {"field": "success_rate"}}
        }
      }
    }
  }
}
```

## 🔧 Dashboard Maintenance

### Regular Updates
1. **Weekly**: Review and adjust time ranges for trending data
2. **Monthly**: Update color schemes and layout based on data patterns
3. **Quarterly**: Add new metrics as research progresses

### Performance Optimization
1. **Limit data ranges** to necessary periods
2. **Use sampling** for large datasets
3. **Cache frequent queries**
4. **Regular index optimization**

## 📈 Thesis Defense Presentation Tips

### Dashboard Presentation Order
1. **Start with Executive Overview** - show overall success
2. **Deep dive into Framework Comparison** - core research findings
3. **Highlight Security Benefits** - practical applications
4. **Conclude with Performance** - technical viability

### Key Talking Points
- **Quantifiable improvements** in each framework
- **Real-world applicability** through security monitoring
- **Performance trade-offs** and optimization strategies
- **Future research directions** based on dashboard insights

## 🚨 Troubleshooting Common Issues

### Data Not Appearing
1. Check data view time ranges
2. Verify field mappings match data structure
3. Confirm Elasticsearch indices are populated
4. Review index patterns and data refresh

### Performance Issues
1. Reduce time range scope
2. Limit number of visualizations per dashboard
3. Use aggregated data views instead of raw events
4. Implement proper caching strategies

### Query Errors
1. Validate field names match exactly
2. Check data types (text vs keyword)
3. Ensure required fields exist in data
4. Test queries in Dev Tools first

This comprehensive dashboard setup will provide powerful visualization capabilities for your Multi-Source MFA ZTA Framework thesis, enabling both technical analysis and compelling presentations for your defense.