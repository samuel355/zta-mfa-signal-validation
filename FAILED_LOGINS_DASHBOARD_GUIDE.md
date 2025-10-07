# Failed Login Attempts Dashboard - Kibana Setup Guide

## 📊 Dashboard Overview
This guide will help you create a "Failed Login Attempts" dashboard in Kibana that shows:
- **Observed Failed Logins** (blue line with dots) - from `proposed_count` field
- **Baseline Logins** (orange dashed line) - from `baseline_count` field
- **Time series** showing hourly patterns over 24 hours

## 🎯 Step-by-Step Kibana Setup

### 1. **Create Data View**
1. Go to **Kibana** → **Stack Management** → **Data Views**
2. Click **"Create data view"**
3. **Name**: `Failed Logins Dashboard`
4. **Index pattern**: `failed-logins*`
5. **Time field**: `@timestamp`
6. Click **"Save data view"**

### 2. **Create Line Chart Visualization**

#### **Step 2.1: Start New Visualization**
1. Go to **Kibana** → **Visualize Library**
2. Click **"Create visualization"**
3. Select **"Line"** chart type
4. Choose **"Failed Logins Dashboard"** data view

#### **Step 2.2: Configure X-Axis (Time)**
1. In **Buckets** section, click **"Add"** → **"X-axis"**
2. **Aggregation**: `Date Histogram`
3. **Field**: `@timestamp`
4. **Interval**: `Hourly` (or `1h`)
5. **Custom label**: `Hour of Day`

#### **Step 2.3: Configure Y-Axis (Metrics)**

**Metric 1 - Observed Failed Logins:**
1. In **Metrics** section, click **"Add"** → **"Y-axis"**
2. **Aggregation**: `Sum`
3. **Field**: `proposed_count`
4. **Custom label**: `Observed Failed Logins`
5. **Color**: Blue (`#1f77b4`)

**Metric 2 - Baseline Logins:**
1. Click **"Add"** → **"Y-axis"** again
2. **Aggregation**: `Sum`
3. **Field**: `baseline_count`
4. **Custom label**: `Baseline Logins`
5. **Color**: Orange (`#ff7f0e`)

#### **Step 2.4: Configure Line Styles**
1. Go to **Panel options** tab
2. **Show markers**: `Yes` (for observed line)
3. **Line width**: `2`
4. **Fill**: `0.1` (light fill under lines)

#### **Step 2.5: Configure Series Options**
1. Go to **Series** tab
2. **Series 1 (Observed Failed Logins)**:
   - **Line style**: `Solid`
   - **Show markers**: `Yes`
   - **Marker size**: `Medium`
3. **Series 2 (Baseline Logins)**:
   - **Line style**: `Dashed`
   - **Show markers**: `No`

### 3. **Styling and Formatting**

#### **Chart Options**
1. **Title**: `Kibana Dashboard Simulation: Failed Login Attempts`
2. **Show legend**: `Yes` (top right)
3. **Show grid**: `Yes`
4. **Y-axis label**: `Failed Login Count`
5. **X-axis label**: `Hour of Day`

#### **Colors**
- **Observed Failed Logins**: Blue (`#1f77b4`)
- **Baseline Logins**: Orange (`#ff7f0e`)

### 4. **Time Range Configuration**
1. Set **time range** to cover at least 24 hours
2. Use **"Last 24 hours"** or **"Last 7 days"**
3. Ensure you have data spanning multiple hours

### 5. **Advanced Configuration (Optional)**

#### **Add Filters**
1. **Add filter** for specific time periods
2. **Add filter** for high-value anomalies (e.g., `proposed_count > 50`)

#### **Add Annotations**
1. **Add annotation** for peak hours
2. **Add annotation** for baseline threshold

## 🔧 Kibana Query Examples

### **Basic Query for Failed Logins**
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h",
              "lte": "now"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "hourly_failed_logins": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      },
      "aggs": {
        "proposed_sum": {
          "sum": {
            "field": "proposed_count"
          }
        },
        "baseline_sum": {
          "sum": {
            "field": "baseline_count"
          }
        }
      }
    }
  }
}
```

### **Anomaly Detection Query**
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h",
              "lte": "now"
            }
          }
        },
        {
          "range": {
            "proposed_count": {
              "gt": 50
            }
          }
        }
      ]
    }
  }
}
```

## 📈 Expected Results

Your dashboard should show:
- **Blue solid line with dots**: Observed failed logins (proposed_count)
- **Orange dashed line**: Baseline failed logins (baseline_count)
- **Time range**: Hourly intervals over 24 hours
- **Peak detection**: Spikes in observed vs stable baseline
- **Anomaly highlighting**: Clear visual difference between normal and abnormal patterns

## 🎯 Dashboard Features

### **Interactive Elements**
- **Hover tooltips**: Show exact values for each hour
- **Zoom functionality**: Click and drag to zoom into specific time ranges
- **Legend**: Click to show/hide individual series
- **Time picker**: Adjust time range dynamically

### **Alerting (Optional)**
1. **Create alert** when `proposed_count > baseline_count * 3`
2. **Set threshold** for anomaly detection
3. **Configure notifications** for security team

## 🚀 Quick Start Commands

### **Check Your Data**
```bash
# Verify failed-logins index has data
curl -X GET "localhost:9200/failed-logins/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "total_records": {
      "value_count": {
        "field": "@timestamp"
      }
    },
    "hourly_breakdown": {
      "date_histogram": {
        "field": "@timestamp",
        "calendar_interval": "1h"
      }
    }
  }
}'
```

### **Access Kibana**
1. Open browser: `http://localhost:5601`
2. Navigate to **Visualize Library**
3. Follow the steps above

## 🎓 Thesis Integration

This dashboard perfectly demonstrates:
- **Framework Comparison**: Baseline vs Proposed detection
- **Anomaly Detection**: Clear visual spikes in failed logins
- **Time Series Analysis**: Hourly patterns and trends
- **Security Monitoring**: Real-time threat detection capabilities

Perfect for your thesis analysis showing the effectiveness of your proposed framework! 🎓✨
