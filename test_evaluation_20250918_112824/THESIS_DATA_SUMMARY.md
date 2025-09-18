# Thesis Data Extraction Summary

Generated: 2025-09-18T11:29:06.322567
Time Period: 24 hours
System Database: Connected

## Files Generated

### Data Files
- `comprehensive_thesis_data.json` - Master data file with all metrics
- `csv_data/` - Individual CSV files for analysis
- `charts/` - Generated charts and figures
- `latex_tables/` - LaTeX table code for thesis
- `kibana_dashboards/` - Dashboard configurations

### Key Metrics Available

#### Framework Comparison
- Decision distribution (Allow/Step-up/Deny)
- Processing time comparison
- Risk score analysis
- Accuracy measurements

#### Security Effectiveness
- Attack detection rates by type
- False positive/negative analysis
- STRIDE threat model coverage
- Multi-source correlation effectiveness

#### Performance Analysis
- Service-level performance metrics
- End-to-end processing times
- System reliability metrics
- Scalability measurements

## Usage Instructions

1. **For Thesis Tables**: Use LaTeX files in `latex_tables/` directory
2. **For Figures**: Use PNG files in `charts/` directory
3. **For Analysis**: Load `comprehensive_thesis_data.json` into analysis tools
4. **For Dashboards**: Import configurations from `kibana_dashboards/`

## Data Refresh

Run this extraction script regularly to get updated metrics:
```bash
python extract_thesis_data.py --hours 168 --output new_extraction/
```
