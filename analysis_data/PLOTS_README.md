# Analysis Plots Documentation

This directory contains high-quality visualization plots for the Zero Trust Multi-Factor Authentication framework analysis.

## Directory Structure

```
analysis_data/
├── fig1_freshness_optimization_hq.png (1.6MB)
├── fig2_geographic_threshold_hq.png (903KB)
├── fig3_threat_penalties_hq.png (1.2MB)
├── fig4_signal_weights_hq.png (2.9MB)
├── fig5_roc_thresholds_hq.png (1.2MB)
├── fig6_siem_weights_hq.png (1.8MB)
├── parameter_optimization_summary.csv (1.2KB)
├── freshness/
│   ├── gps_freshness_optimization.png (555KB)
│   ├── ip_freshness_optimization.png (571KB)
│   ├── device_freshness_optimization.png (515KB)
│   ├── wifi_freshness_optimization.png (524KB)
│   └── tls_freshness_optimization.png (568KB)
├── threat_penalties/
│   ├── vpn_penalty_optimization.png (493KB)
│   ├── tor_penalty_optimization.png (486KB)
│   ├── malicious_penalty_optimization.png (459KB)
│   └── unknown_penalty_optimization.png (474KB)
└── roc_analysis/
    ├── roc_curve_with_thresholds.png (611KB)
    └── f1_score_vs_threshold.png (503KB)
```

## Combined Plots (Original Designs)

These are comprehensive multi-panel plots showing all related optimizations together:

### 1. `fig1_freshness_optimization_hq.png`
- **Description**: 2x3 grid showing optimization of freshness time constants for all contextual signals
- **Signals**: GPS (5 min), IP (10 min), Device (24h), Wi-Fi (30 min), TLS (20 min)
- **Resolution**: 600 DPI
- **Use Case**: Overview comparison of all signal freshness windows

### 2. `fig2_geographic_threshold_hq.png`
- **Description**: Geographic consistency threshold (d₀) optimization with dual Y-axes
- **Optimal Value**: 1000 km
- **Metrics**: F1-Score and False Positive Rate
- **Use Case**: Impossible travel detection analysis

### 3. `fig3_threat_penalties_hq.png`
- **Description**: 2x2 grid showing threat intelligence penalty weight optimization
- **Penalties**: VPN (0.7), TOR (0.9), Malicious IP (0.1), Unknown IP (0.2)
- **Resolution**: 600 DPI
- **Use Case**: Threat detection parameter tuning

### 4. `fig4_signal_weights_hq.png`
- **Description**: Parallel coordinates plot for signal weight optimization
- **Optimal Weights**: GPS (0.25), IP (0.20), Device (0.20), TLS (0.20), Wi-Fi (0.15)
- **Resolution**: 600 DPI
- **Use Case**: Multi-signal weighting strategy visualization

### 5. `fig5_roc_thresholds_hq.png`
- **Description**: Dual-panel ROC analysis with threshold optimization
- **Thresholds**: Step-up (0.25), Deny (0.75)
- **Panels**: ROC curve with decision points, F1-Score vs threshold
- **Use Case**: Risk-based authentication threshold selection

### 6. `fig6_siem_weights_hq.png`
- **Description**: Contour plot for SIEM alert weight optimization
- **Optimal Values**: High-severity (0.30), Medium-severity (0.15)
- **Resolution**: 600 DPI
- **Use Case**: SIEM integration weight tuning

## Individual Plots (New Standalone Designs)

Clean, standalone plots without bottom captions for presentation and publication use.

### Freshness Optimization (`freshness/` folder)

Individual time constant optimization plots for each contextual signal:

1. **`gps_freshness_optimization.png`**
   - Optimal: 5 minutes (F1=0.90)
   - Rationale: Prevents GPS replay attacks while allowing mobility

2. **`ip_freshness_optimization.png`**
   - Optimal: 10 minutes (F1=0.89)
   - Rationale: Accommodates dynamic IP address changes

3. **`device_freshness_optimization.png`**
   - Optimal: 1440 minutes / 24 hours (F1=0.88)
   - Rationale: Matches daily security assessment cycles

4. **`wifi_freshness_optimization.png`**
   - Optimal: 30 minutes (F1=0.81)
   - Rationale: Balances mobility and contextual consistency

5. **`tls_freshness_optimization.png`**
   - Optimal: 20 minutes (F1=0.86)
   - Rationale: Detects client tampering in a timely manner

**Common Features:**
- X-axis: Time constant (minutes, log scale)
- Y-axis: F1-Score (0.55 - 0.96)
- Red square markers indicate optimal points
- Smooth interpolation curves for trend visualization

### Threat Penalty Optimization (`threat_penalties/` folder)

Individual penalty weight optimization plots for threat indicators:

1. **`vpn_penalty_optimization.png`**
   - Optimal: 0.70 (F1=0.93)
   - Rationale: Strongly penalizes but allows legitimate VPN use

2. **`tor_penalty_optimization.png`**
   - Optimal: 0.90 (F1=0.94)
   - Rationale: Very high risk indicator for TOR exit nodes

3. **`malicious_penalty_optimization.png`**
   - Optimal: 0.10 (F1=0.88)
   - Rationale: Modest penalty for volatile IP reputation databases

4. **`unknown_penalty_optimization.png`**
   - Optimal: 0.20 (F1=0.89)
   - Rationale: Discounts unknown IPs without over-penalizing

**Common Features:**
- X-axis: Penalty Weight (0 - 1)
- Y-axis: F1-Score (0.68 - 0.96)
- Red square markers indicate optimal points
- Smooth interpolation curves for trend visualization

### ROC Analysis (`roc_analysis/` folder)

Separated ROC analysis components for detailed examination:

1. **`roc_curve_with_thresholds.png`**
   - **Description**: ROC curve showing True Positive Rate vs False Positive Rate
   - **AUC**: ~0.9
   - **Decision Points**: 
     - Step-up threshold (R=0.25): Red circle marker
     - Deny threshold (R=0.75): Green square marker
   - **Use Case**: Security vs usability trade-off visualization

2. **`f1_score_vs_threshold.png`**
   - **Description**: F1-Score performance across all risk thresholds
   - **Highlighted Regions**:
     - Step-up region (0.2-0.3): Red shaded area
     - Deny region (0.7-0.8): Green shaded area
   - **Optimal Points**: Marked at 0.25 and 0.75 thresholds
   - **Use Case**: Threshold selection and performance analysis

## Technical Specifications

### All Plots
- **Resolution**: 600 DPI (publication quality)
- **Font Family**: Times New Roman (academic standard)
- **Format**: PNG with transparent backgrounds where applicable
- **Color Palette**: Professional, colorblind-friendly colors
- **Grid Style**: Light gray dashed lines (alpha=0.3)

### Font Sizes (Individual Plots)
- Title: 18pt, bold
- Axis Labels: 16pt, bold
- Tick Labels: 14pt
- Legend: 13pt

### Font Sizes (Combined Plots)
- Super Title: 18pt, bold
- Subplot Titles: 16pt, bold
- Axis Labels: 14pt
- Tick Labels: 12pt
- Legend: 11pt

## Data Files

### `parameter_optimization_summary.csv`
Comprehensive summary table containing:
- Parameter names
- Optimal values
- F1-Score performance metrics
- Justifications for each optimal value

**Columns:**
- `Parameter`: Name of the optimization parameter
- `Optimal_Value`: Best performing value
- `F1_Score`: Performance metric at optimal value
- `Justification`: Rationale for the optimal choice

## Generation Scripts

### `plot_analysis.py`
Generates all combined multi-panel plots (fig1-fig6) and the summary CSV.

**Usage:**
```bash
cd analysis_data
python3 plot_analysis.py
```

### `generate_individual_plots.py`
Generates all individual standalone plots organized in subdirectories.

**Usage:**
```bash
cd analysis_data
python3 generate_individual_plots.py
```

## Use Cases

### For Research Papers
- **Overview**: Use combined plots (fig1-fig6) in main paper
- **Detailed Analysis**: Use individual plots in appendix or supplementary materials
- **Tables**: Reference `parameter_optimization_summary.csv` for numerical values

### For Presentations
- **Slides**: Use individual plots (larger, cleaner, easier to read)
- **Comparison Slides**: Use combined plots for side-by-side comparisons
- **Technical Talks**: Use ROC analysis plots for security metrics discussion

### For Technical Documentation
- **System Design**: Reference optimal values from individual plots
- **Tuning Guide**: Use plots to understand parameter sensitivity
- **Performance Reports**: Include ROC curves and F1-score analysis

## Optimal Parameter Summary

| Parameter | Optimal Value | F1-Score | Category |
|-----------|---------------|----------|----------|
| GPS Freshness | 5 min | 0.90 | Freshness |
| IP Freshness | 10 min | 0.89 | Freshness |
| Device Freshness | 24 h | 0.88 | Freshness |
| WiFi Freshness | 30 min | 0.81 | Freshness |
| TLS Freshness | 20 min | 0.86 | Freshness |
| Geographic Threshold d₀ | 1000 km | 0.94 | Consistency |
| VPN Penalty | 0.70 | 0.93 | Threat Intel |
| TOR Penalty | 0.90 | 0.94 | Threat Intel |
| Malicious IP Penalty | 0.10 | 0.88 | Threat Intel |
| Unknown IP Penalty | 0.20 | 0.89 | Threat Intel |
| GPS Weight | 0.25 | 0.92 | Signal Weight |
| IP Weight | 0.20 | 0.92 | Signal Weight |
| Device Weight | 0.20 | 0.92 | Signal Weight |
| TLS Weight | 0.20 | 0.92 | Signal Weight |
| WiFi Weight | 0.15 | 0.92 | Signal Weight |
| Step-up Threshold | 0.25 | 0.88 | Risk Threshold |
| Deny Threshold | 0.75 | 0.74 | Risk Threshold |
| SIEM High Weight | 0.30 | 0.93 | SIEM |
| SIEM Medium Weight | 0.15 | 0.93 | SIEM |

## Notes

- All plots use consistent color schemes for easy visual recognition
- Optimal points are consistently marked with red square markers
- Smooth interpolation curves help visualize trends between data points
- Grid lines are subtle to avoid cluttering the visualization
- Legends are positioned to not overlap with data
- No bottom captions on individual plots for cleaner presentation
- Original combined plots are preserved for reference and comparison

---

**Generated by:** Zero Trust MFA Analysis Framework  
**Last Updated:** February 1, 2024  
**Version:** 1.0