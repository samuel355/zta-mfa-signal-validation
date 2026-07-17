#!/usr/bin/env python3
"""Second pass: table cell corrections (run after apply_thesis_corrections.py)."""
import docx

PATH = "/Users/knight/Apps/multi-source-ztamfa/updated/Multi- Source Context-Validation Zero Trust Framework - CORRECTED.docx"

d = docx.Document(PATH)
tables = d.tables


def set_cell(table_idx, row, col, new_text):
    tables[table_idx].rows[row].cells[col].text = new_text


# Table 4 (Table 4.1: Security Accuracy) — columns: Metric | Proposed | Ahmadi | Jimmy | Phani
set_cell(4, 1, 1, "88.30%"); set_cell(4, 1, 2, "21.86%"); set_cell(4, 1, 3, "Excluded — no published formula"); set_cell(4, 1, 4, "6.11%")
set_cell(4, 2, 1, "2.86%");  set_cell(4, 2, 2, "5.71%");  set_cell(4, 2, 3, "Excluded — no published formula"); set_cell(4, 2, 4, "1.90%")
set_cell(4, 3, 1, "99.83%"); set_cell(4, 3, 2, "98.61%"); set_cell(4, 3, 3, "Excluded — no published formula"); set_cell(4, 3, 4, "98.35%")
set_cell(4, 4, 1, "0.937");  set_cell(4, 4, 2, "0.358");  set_cell(4, 4, 3, "Excluded — no published formula"); set_cell(4, 4, 4, "0.115")
set_cell(4, 5, 0, "Detection accuracy (TP+TN / total)")
set_cell(4, 5, 1, "88.75%"); set_cell(4, 5, 2, "25.56%"); set_cell(4, 5, 3, "Excluded — no published formula"); set_cell(4, 5, 4, "10.81%")

# Table 5 (Table 4.2: Performance) — columns: Metric | Proposed | Ahmadi | Jimmy | Phani
set_cell(5, 1, 0, "End-to-end Decision Latency (median / p95)")
set_cell(5, 1, 1, "47ms / 2142ms"); set_cell(5, 1, 2, "13ms / 18ms"); set_cell(5, 1, 3, "Excluded"); set_cell(5, 1, 4, "13ms / 18ms")
set_cell(5, 2, 0, "Architecture")
set_cell(5, 2, 1, "3-service chain + external enrichment calls (GeoIP, WiGLE, SIEM)")
set_cell(5, 2, 2, "Single-hop, no external calls")
set_cell(5, 2, 3, "Excluded")
set_cell(5, 2, 4, "Single-hop, no external calls")
set_cell(5, 3, 0, "Baseline Auth Latency"); set_cell(5, 3, 1, "n/a"); set_cell(5, 3, 2, "n/a"); set_cell(5, 3, 3, "Excluded"); set_cell(5, 3, 4, "n/a")
set_cell(5, 4, 1, "No degradation observed under test load")
set_cell(5, 5, 1, "Not independently profiled this cycle")

# Table 6 & 7 (Table 4.3: Usability, duplicated table) — columns: Metric | Proposed | Ahmadi | Jimmy | Phani
for ti in (6, 7):
    set_cell(ti, 1, 0, "Step-up Challenge Rate")
    set_cell(ti, 1, 1, "70.79% (measured directly; dataset is 95% malicious by construction, not a before/after reduction)")
    set_cell(ti, 1, 2, "10.91%"); set_cell(ti, 1, 3, "Excluded"); set_cell(ti, 1, 4, "5.06%")
    set_cell(ti, 2, 0, "Session Continuity Rate")
    set_cell(ti, 2, 1, "Not measured this cycle — current architecture evaluates single-shot sessions")
    set_cell(ti, 2, 2, "Not measured"); set_cell(ti, 2, 3, "Excluded"); set_cell(ti, 2, 4, "Not measured")
    set_cell(ti, 3, 0, "False Positive Rate")
    set_cell(ti, 3, 1, "2.86%"); set_cell(ti, 3, 2, "5.71%"); set_cell(ti, 3, 3, "Excluded"); set_cell(ti, 3, 4, "1.90%")

# Table 8 (Table 4.5: Statistical Significance) — real McNemar results
set_cell(8, 0, 0, "Comparison"); set_cell(8, 0, 1, "Metric"); set_cell(8, 0, 2, "Test"); set_cell(8, 0, 3, "Statistic"); set_cell(8, 0, 4, "p-value")
set_cell(8, 1, 0, "Proposed vs Ablation"); set_cell(8, 1, 1, "Paired classification"); set_cell(8, 1, 2, "McNemar's (χ², continuity-corrected)"); set_cell(8, 1, 3, "χ² = 557.5"); set_cell(8, 1, 4, "p < 0.001")
set_cell(8, 2, 0, "Proposed vs Ahmadi (2025)"); set_cell(8, 2, 1, "Paired classification"); set_cell(8, 2, 2, "McNemar's (χ², continuity-corrected)"); set_cell(8, 2, 3, "χ² = 1261.9"); set_cell(8, 2, 4, "p < 0.001")
set_cell(8, 3, 0, "Proposed vs Phani (2025)"); set_cell(8, 3, 1, "Paired classification"); set_cell(8, 3, 2, "McNemar's (χ², continuity-corrected)"); set_cell(8, 3, 3, "χ² = 1585.1"); set_cell(8, 3, 4, "p < 0.001")
set_cell(8, 4, 0, ""); set_cell(8, 4, 1, ""); set_cell(8, 4, 2, ""); set_cell(8, 4, 3, ""); set_cell(8, 4, 4, "")
set_cell(8, 5, 0, ""); set_cell(8, 5, 1, ""); set_cell(8, 5, 2, ""); set_cell(8, 5, 3, ""); set_cell(8, 5, 4, "")
set_cell(8, 6, 0, "Note"); set_cell(8, 6, 1, "McNemar's test (paired binary outcomes on matched sessions) replaces the paired t-test originally reported here, which was the wrong test for this data type."); set_cell(8, 6, 2, ""); set_cell(8, 6, 3, ""); set_cell(8, 6, 4, "")

# Table 9 (Table 4.6: Ablation Results) — only one real configuration measured
set_cell(9, 0, 0, "Configuration"); set_cell(9, 0, 1, "TPR"); set_cell(9, 0, 2, "FPR"); set_cell(9, 0, 3, "F1-Score"); set_cell(9, 0, 4, "Step-up Rate")
set_cell(9, 1, 0, "Full Framework"); set_cell(9, 1, 1, "88.30%"); set_cell(9, 1, 2, "2.86%"); set_cell(9, 1, 3, "0.937"); set_cell(9, 1, 4, "70.79%")
set_cell(9, 2, 0, "Validation Layer Disabled (ablation)"); set_cell(9, 2, 1, "52.13%"); set_cell(9, 2, 2, "20.95%"); set_cell(9, 2, 3, "0.680"); set_cell(9, 2, 4, "42.60%")
set_cell(9, 3, 0, "Without Geographic Cross-Validation only"); set_cell(9, 3, 1, "Not measured this cycle"); set_cell(9, 3, 2, "—"); set_cell(9, 3, 3, "—"); set_cell(9, 3, 4, "—")
set_cell(9, 4, 0, "Without SIEM Integration only"); set_cell(9, 4, 1, "Not measured this cycle"); set_cell(9, 4, 2, "—"); set_cell(9, 4, 3, "—"); set_cell(9, 4, 4, "—")
set_cell(9, 5, 0, "Without TLS Fingerprinting only"); set_cell(9, 5, 1, "Not measured this cycle"); set_cell(9, 5, 2, "—"); set_cell(9, 5, 3, "—"); set_cell(9, 5, 4, "—")

# Table 11 (Table 4.8: was "Adversarial Attack Detection Rates by type") — replace with real per-STRIDE breakdown
set_cell(11, 0, 0, "STRIDE Category"); set_cell(11, 0, 1, "Proposed"); set_cell(11, 0, 2, "Ahmadi (2025) / Phani (2025)")
set_cell(11, 1, 0, "Spoofing"); set_cell(11, 1, 1, "100%"); set_cell(11, 1, 2, "72% / 24%")
set_cell(11, 2, 0, "Tampering"); set_cell(11, 2, 1, "51%"); set_cell(11, 2, 2, "8% / 2%")
set_cell(11, 3, 0, "Repudiation"); set_cell(11, 3, 1, "45%"); set_cell(11, 3, 2, "9% / 1%")
set_cell(11, 4, 0, "Information Disclosure"); set_cell(11, 4, 1, "100%"); set_cell(11, 4, 2, "11% / 2%")
set_cell(11, 5, 0, "Denial of Service"); set_cell(11, 5, 1, "100%"); set_cell(11, 5, 2, "10% / 1%")
set_cell(11, 6, 0, "Elevation of Privilege"); set_cell(11, 6, 1, "100%"); set_cell(11, 6, 2, "10% / 2%")

# Table 12 (Table 4.9: Network Condition Sensitivity) — flag as stale, keep old numbers but annotate
set_cell(12, 0, 1, "Avg Latency (stale — pre-final-calibration)"); set_cell(12, 0, 2, "TPR (stale)"); set_cell(12, 0, 3, "FPR (stale)")
set_cell(12, 1, 1, "680ms"); set_cell(12, 1, 2, "61.0%"); set_cell(12, 1, 3, "0%")
set_cell(12, 2, 1, "807ms"); set_cell(12, 2, 2, "62.1%"); set_cell(12, 2, 3, "0%")
set_cell(12, 3, 1, "876ms"); set_cell(12, 3, 2, "62.2%"); set_cell(12, 3, 3, "0%")

# Table 13 (Table 4.10: Hypothesis Evaluation Summary)
set_cell(13, 1, 1, "Supported")
set_cell(13, 1, 2, "88.30% TPR, 2.86% FPR. Significantly outperforms ablation and both re-implemented baselines (McNemar's test, p < 0.001).")
set_cell(13, 2, 1, "Supported")
set_cell(13, 2, 2, "FPR 2.86% vs 20.95% (ablation, validation layer disabled) and 5.71%/1.90% (baselines), with TPR simultaneously improved, not traded off.")
set_cell(13, 3, 1, "Partially supported")
set_cell(13, 3, 2, "SIEM correlation provides STRIDE-classified alerting unavailable in any baseline; its specific quantitative TPR contribution was not isolated in a controlled experiment this cycle.")
set_cell(13, 4, 1, "Partially supported")
set_cell(13, 4, 2, "Median latency 47ms meets the 50ms threshold; p95 latency 2.1s does not, driven by external enrichment calls.")
set_cell(13, 5, 1, "Implemented, not independently audited")
set_cell(13, 5, 2, "HMAC-SHA-256 hashing and bounded retention are implemented; a formal privacy-leakage audit was not performed this cycle.")

d.save(PATH)
print("Saved table edits.")
