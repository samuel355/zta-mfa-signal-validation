# Thesis Data Extraction Guide

This guide provides comprehensive instructions for extracting real metrics, tables, charts, and dashboard data from your Multi-Source MFA ZTA Framework to replace placeholder content in your thesis document.

## 📋 Overview

The framework provides multiple extraction tools to get actual data for:
- Framework performance comparison tables
- Security effectiveness metrics
- System performance charts
- Kibana dashboard screenshots
- LaTeX tables for thesis
- Key performance indicators (KPIs)

## 🚀 Quick Start

### 1. Extract All Thesis Data (Recommended)

```bash
# Run the comprehensive extraction
cd multi-souce-mfa-zta-framework/scripts
python3 extract_thesis_data.py --hours 168 --output ../thesis_data_$(date +%Y%m%d)

# Or for quick extraction (last 24 hours)
python3 quick_thesis_extract.py --hours 24 --format both
```

### 2. Setup Kibana Dashboards

```bash
# Generate Kibana dashboard configurations
python3 create_kibana_dashboards.py --create-all --kibana-url http://localhost:5601

# Or generate manual setup instructions
python3 create_kibana_dashboards.py --manual-instructions --export-configs
```

## 📊 Data Sources Available

### Framework Comparison Data
- **Total authentication events processed**
- **Decision distribution (Allow/Step-up/Deny) by framework**
- **Average processing time comparison**
- **Risk score distribution analysis**
- **Classification accuracy metrics**

### Security Effectiveness Metrics
- **STRIDE threat detection rates**
- **Attack type recognition accuracy**
- **False positive/negative analysis**
- **Multi-source correlation effectiveness**
- **Threat severity distribution**

### Performance Analysis
- **Service-level response times**
- **System throughput metrics**
- **Error rates and reliability**
- **Resource utilization statistics**

## 🔧 Extraction Tools

### 1. Comprehensive Extraction (`extract_thesis_data.py`)

**Features:**
- Complete framework comparison analysis
- Security effectiveness evaluation
- Performance metrics collection
- Chart generation for thesis figures
- LaTeX table export
- Kibana dashboard configurations

**Usage:**
```bash
# Full extraction (7 days of data)
python extract_thesis_data.py --hours 168 --output thesis_data_full/

# Framework comparison only
python extract_thesis_data.py --comparison-only --hours 72

# Dashboard export only
python extract_thesis_data.py --dashboard-export --kibana-url http://localhost:5601
```

**Output Files:**
```
thesis_data_full/
├── comprehensive_thesis_data.json      # Master data file
├── csv_data/
│   ├── framework_performance.csv       # Performance comparison
│   ├── security_effectiveness.csv      # Security metrics
│   └── system_metrics.csv             # System performance
├── charts/
│   ├── framework_comparison.png        # Framework comparison chart
│   ├── security_effectiveness.png      # Security effectiveness chart
│   └── performance_trends.png         # Performance trend analysis
├── latex_tables/
│   ├── framework_comparison.tex        # LaTeX table code
│   ├── security_effectiveness.tex      # Security effectiveness table
│   └── performance_metrics.tex        # Performance comparison table
├── kibana_dashboards/
│   ├── dashboards_list.json           # Available dashboards
│   ├── sample_dashboard_config.json   # Dashboard configuration
│   └── dashboard_export.json          # Exported dashboard data
└── THESIS_DATA_SUMMARY.md             # Human-readable summary
```

### 2. Quick Extraction (`quick_thesis_extract.py`)

**Features:**
- Fast data extraction for immediate use
- Key metrics summary for thesis abstract
- Ready-to-use tables and values
- Thesis integration instructions

**Usage:**
```bash
# Quick extraction (24 hours)
python quick_thesis_extract.py --hours 24

# Extended period extraction
python quick_thesis_extract.py --hours 168 --format both --output quick_extract_7days/
```

**Output Files:**
```
thesis_extract_20241215_143022/
├── raw_metrics_data.json              # Raw extracted data
├── thesis_key_metrics.json            # Key metrics for thesis
├── THESIS_METRICS_SUMMARY.md          # Human-readable summary
├── QUICK_REFERENCE.md                 # Integration instructions
└── tables/
    ├── framework_comparison.csv        # Framework comparison table
    ├── framework_comparison.tex        # LaTeX format
    ├── decision_distribution.csv       # Decision distribution
    └── system_performance.csv         # System performance
```

### 3. Kibana Dashboard Creator (`create_kibana_dashboards.py`)

**Features:**
- Automated dashboard creation
- Index pattern setup
- Visualization configuration
- Manual setup instructions
- Dashboard export capabilities

**Usage:**
```bash
# Create all dashboards automatically
python create_kibana_dashboards.py --create-all

# Generate manual setup instructions
python create_kibana_dashboards.py --manual-instructions --output kibana_setup/

# Export existing dashboard configurations
python create_kibana_dashboards.py --export-configs
```

**Generated Dashboards:**
1. **Multi-Source MFA Framework Overview**
   - Authentication decision distribution
   - Risk score histogram
   - Events timeline
   - Framework performance comparison

2. **Security Effectiveness Dashboard**
   - STRIDE category breakdown
   - Alert severity distribution
   - Attack timeline analysis
   - Threat detection effectiveness

3. **Performance Monitoring Dashboard**
   - Response time trends
   - Service health status
   - System throughput metrics
   - Error rate monitoring

4. **Thesis Comparison Dashboard**
   - Side-by-side framework comparison
   - Decision accuracy analysis
   - Processing time comparison
   - Detection effectiveness metrics

## 📈 Using Extracted Data in Your Thesis

### 1. Replacing Placeholder Tables

**LaTeX Integration:**
```latex
% Replace your placeholder table with generated LaTeX
\input{thesis_data_full/latex_tables/framework_comparison.tex}
```

**CSV Data for Custom Tables:**
- Load CSV files into Excel/Google Sheets
- Create custom formatting and styling
- Export as images or recreate in LaTeX

### 2. Key Metrics for Text

**Example replacements from `THESIS_METRICS_SUMMARY.md`:**

```markdown
# Before (Placeholder)
The proposed framework processed XXXX authentication events...

# After (Real Data)
The proposed framework processed 15,847 authentication events...
```

**Common Thesis Metrics:**
```json
{
  "total_authentication_events": 15847,
  "system_success_rate_percent": 94.2,
  "mfa_stepup_rate_percent": 23.1,
  "threat_detection_accuracy_percent": 87.6,
  "false_positive_rate_percent": 3.8,
  "system_availability_percent": 99.1
}
```

### 3. Charts and Figures

**Generated Charts:**
- `framework_comparison.png` - Framework performance comparison
- `security_effectiveness.png` - Attack detection rates by type
- `performance_trends.png` - System performance over time

**Usage in LaTeX:**
```latex
\begin{figure}[htbp]
  \centering
  \includegraphics[width=0.8\textwidth]{figures/framework_comparison.png}
  \caption{Framework Performance Comparison}
  \label{fig:framework_comparison}
\end{figure}
```

### 4. Dashboard Screenshots

**Manual Screenshot Process:**
1. Access dashboards at `http://localhost:5601/app/dashboards`
2. Navigate to created dashboards:
   - Multi-Source MFA Framework Overview
   - Security Effectiveness Dashboard
   - Thesis Comparison Dashboard
3. Set appropriate time range (Last 7 days recommended)
4. Take high-resolution screenshots
5. Use in thesis figures

**Automated Screenshots (Advanced):**
```bash
# If you have headless browser tools installed
python capture_dashboard_screenshots.py --kibana-url http://localhost:5601
```

## 🔍 Data Validation and Quality

### 1. Verify Data Completeness

**Check Database Connection:**
```python
python -c "
import os
from sqlalchemy import create_engine, text
dsn = os.getenv('DB_DSN', 'postgresql://postgres:password@localhost:5432/postgres')
engine = create_engine(dsn)
with engine.connect() as conn:
    result = conn.execute(text('SELECT COUNT(*) FROM zta.framework_comparison'))
    print(f'Framework comparison records: {result.scalar()}')
"
```

**Check Service Health:**
```bash
# Check all services are responding
curl -s http://localhost:8030/health | jq '.'  # Metrics service
curl -s http://localhost:8020/health | jq '.'  # Baseline service
curl -s http://localhost:8003/health | jq '.'  # Gateway service
curl -s http://localhost:8001/health | jq '.'  # Validation service
```

### 2. Data Quality Indicators

**Look for these in extracted data:**
- **Total events > 1000** (sufficient sample size)
- **Multiple framework types** (proposed and baseline)
- **Variety in decisions** (allow, step_up, deny)
- **Risk score distribution** (0.0 to 1.0 range)
- **Processing times > 0** (services are working)

### 3. Common Issues and Solutions

**Issue: No data extracted**
```bash
# Solution: Check if simulator has run recently
python scripts/simulator/run_enhanced.py --hours 1 --max-rows 100
```

**Issue: Only baseline data available**
```bash
# Solution: Ensure proposed framework services are running
docker-compose -f compose/docker-compose.yml up validation trust gateway
```

**Issue: Empty Kibana dashboards**
```bash
# Solution: Check Elasticsearch indices exist
curl -s http://localhost:9200/_cat/indices | grep -E "(mfa-events|siem-alerts|validated-context)"
```

## 📋 Thesis Integration Checklist

### Before Extraction
- [ ] System is running (all services healthy)
- [ ] Simulator has generated sufficient data (>1000 events)
- [ ] Database is accessible and populated
- [ ] Kibana/Elasticsearch are running
- [ ] Time period selected (recommend 7 days minimum)

### Data Extraction
- [ ] Run comprehensive extraction script
- [ ] Verify output files are generated
- [ ] Check data quality in summary files
- [ ] Review key metrics for reasonableness
- [ ] Generate Kibana dashboards
- [ ] Take dashboard screenshots

### Thesis Integration
- [ ] Replace placeholder tables with LaTeX files
- [ ] Update key metrics in thesis text
- [ ] Include generated charts in figures
- [ ] Add dashboard screenshots
- [ ] Update methodology section with actual parameters
- [ ] Verify all placeholder values are replaced

### Final Validation
- [ ] Cross-check metrics between different extraction methods
- [ ] Verify charts match table data
- [ ] Ensure all figures have proper captions and labels
- [ ] Check that methodology describes actual implementation
- [ ] Review conclusions align with extracted data

## 🛠️ Troubleshooting

### Common Error Messages

**"Database connection unavailable"**
```bash
# Check database connection string
echo $DB_DSN
# Test connection
python scripts/test_db_connection.py
```

**"Service timeout or unreachable"**
```bash
# Check service status
docker-compose -f compose/docker-compose.yml ps
# Restart services if needed
docker-compose -f compose/docker-compose.yml restart
```

**"No data in specified time range"**
```bash
# Check data timestamps
python -c "
from sqlalchemy import create_engine, text
import os
engine = create_engine(os.getenv('DB_DSN'))
with engine.connect() as conn:
    result = conn.execute(text('SELECT MIN(created_at), MAX(created_at), COUNT(*) FROM zta.framework_comparison'))
    print('Data range:', result.fetchone())
"
```

### Performance Optimization

**For large datasets:**
- Use shorter time ranges (24-72 hours)
- Extract data in chunks
- Focus on specific metrics rather than comprehensive extraction

**For faster extraction:**
- Use `quick_thesis_extract.py` for immediate needs
- Parallel extraction (run multiple scripts simultaneously)
- Cache frequently accessed data

## 📞 Support and Resources

### Log Files
- Service logs: `logs/service_name.log`
- Extraction logs: Check console output during script execution
- Database logs: Check PostgreSQL/Supabase logs

### Validation Scripts
- `scripts/test_db_connection.py` - Test database connectivity
- `scripts/verify_data_insertion.py` - Verify data quality
- `scripts/health_check.py` - Check all services

### Documentation References
- `SYSTEM_ARCHITECTURE.md` - System overview and data flow
- `SETUP_GUIDE.md` - Initial system setup
- Service-specific README files in `services/*/`

---

**Generated for Multi-Source MFA ZTA Framework Thesis Project**
*Last Updated: December 2024*

For additional support or custom extraction requirements, refer to the service-specific documentation or modify the extraction scripts according to your thesis needs.