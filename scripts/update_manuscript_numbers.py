#!/usr/bin/env python3
"""One-time text substitution of build_manuscript_docx.py's hardcoded numbers
to match the final, clean, collision-free thesis re-run (n=5,521,
scripts/chapter4_metrics.json / roc_data.json). Run once, then regenerate the
manuscript with `python3 build_manuscript_docx.py`."""
import re

PATH = "build_manuscript_docx.py"
src = open(PATH).read()

REPLACEMENTS = [
    ("n = 2,054", "n = 5,521"),
    ("88.3% TPR, 2.86% FPR, 99.83% precision, and", "98.9% TPR, 0.00% FPR, 100.00% precision, and"),
    ("F1 = 0.937 (AUC = 0.968), outperforming both baselines and the ablation",
     "F1 = 0.995 (AUC = 0.995), outperforming both baselines and the ablation"),
    ("is 2.1 s, reflecting", "is 2.3 s, reflecting"),
    ("Median decision latency is 47 ms;", "Median decision latency is 71 ms;"),
    ("n = 2,678 malicious / 195 benign sessions, AUC = 0.968",
     "n = 5,172 malicious / 349 benign sessions, AUC = 0.995"),
    ('["TPR",        "88.30%", "52.13%", "21.86%", "6.11%"],',
     '["TPR",        "98.92%", "34.07%", "20.96%", "10.71%"],'),
    ('["FPR",        "2.86%",  "20.95%", "5.71%",  "1.90%"],',
     '["FPR",        "0.00%",  "0.00%",  "9.17%",  "1.43%"],'),
    ('["Precision",  "99.83%", "97.88%", "98.61%", "98.35%"],',
     '["Precision",  "100.00%","100.00%","97.13%", "99.11%"],'),
    ('["F1-Score",   "0.937",  "0.680",  "0.358",  "0.115"],',
     '["F1-Score",   "0.995",  "0.508",  "0.345",  "0.193"],'),
    ('["AUC",        "0.968",  "—",      "0.572",  "0.582"],',
     '["AUC",        "0.995",  "—",      "0.563",  "0.575"],'),
    ('caption_text="Security accuracy comparison (n = 2,054 sessions/configuration).",',
     'caption_text="Security accuracy comparison (n = 5,521 sessions/configuration).",'),
    ("Ahmadi's 21.86% aggregate TPR", "Ahmadi's 20.96% aggregate TPR"),
    ("TPR = 52.13%, FPR = 20.95%) isolates", "TPR = 34.07%, FPR = 0.00%) isolates"),
    ('"The proposed framework\'s step-up rate is 70.79% on the evaluation "',
     '"The proposed framework\'s step-up rate is 80.09% on the evaluation "'),
    ('"usability signal is FPR (2.86%): legitimate sessions are rarely "\n        "challenged unnecessarily, in contrast to the ablation "\n        "configuration\'s 20.95% FPR (Figure 7). A session-continuity metric "',
     '"usability signal is FPR (0.00%), tied with the ablation configuration on "\n        "this run\'s small benign sample (n=349) but achieved alongside a far "\n        "higher TPR (98.92% vs 34.07%) — the validation layer\'s benefit shows "\n        "up primarily as detection improvement here, not FPR reduction "\n        "(Figure 7). A session-continuity metric "'),
    ('["Median Latency",     "47 ms",   "14 ms", "13 ms", "13 ms"],',
     '["Median Latency",     "71 ms",   "16 ms", "15 ms", "14 ms"],'),
    ('["p95 Latency",        "2,142 ms","20 ms", "18 ms", "18 ms"],',
     '["p95 Latency",        "2,287 ms","42 ms", "39 ms", "38 ms"],'),
    ('"Median latency (47 ms) is low, but 95th-percentile latency "\n        "(2.1 s) is substantially higher and more variable than the "\n        "single-hop baselines (13-14 ms median throughout).',
     '"Median latency (71 ms) is low, but 95th-percentile latency "\n        "(2.3 s) is substantially higher and more variable than the "\n        "single-hop baselines (14-16 ms median throughout).'),
    ('["Proposed vs Ablation",              "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 557.5",  "p < 0.001"],',
     '["Proposed vs Ablation",              "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 3352.0", "p < 0.001"],'),
    ('["Proposed vs Ahmadi (2025)",         "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 1261.9", "p < 0.001"],',
     '["Proposed vs Ahmadi (2025)",         "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 4052.0", "p < 0.001"],'),
    ('["Proposed vs Phani Kumar Kanuri (2025)", "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 1585.1", "p < 0.001"],',
     '["Proposed vs Phani Kumar Kanuri (2025)", "McNemar\'s (chi-squared, continuity-corrected)", "χ² = 4557.0", "p < 0.001"],'),
    ('["Full Framework",                     "88.30%", "2.86%",  "0.937"],',
     '["Full Framework",                     "98.92%", "0.00%",  "0.995"],'),
    ('["Validation Layer Disabled (ablation)","52.13%", "20.95%", "0.680"],',
     '["Validation Layer Disabled (ablation)","34.07%", "0.00%",  "0.508"],'),
    ('"Disabling the validation layer entirely drops TPR from 88.30% to "\n        "52.13% and raises FPR from 2.86% to 20.95%, confirming its major "',
     '"Disabling the validation layer entirely drops TPR from 98.92% to "\n        "34.07%, confirming its major contribution to detection. FPR is 0.00% "\n        "for both configurations on this run\'s small benign sample (n=349), so "\n        "the validation layer\'s benefit shows up here as detection rather than "'),
    ("with this paper's other results (88.30% TPR)", "with this paper's other results (98.92% TPR)"),
    ('"improvements across every security accuracy metric: 88.3% TPR, "\n        "2.86% FPR, and F1 = 0.937 (McNemar\'s test, p < 0.001 vs every "',
     '"improvements across every security accuracy metric: 98.9% TPR, "\n        "0.00% FPR, and F1 = 0.995 (McNemar\'s test, p < 0.001 vs every "'),
    ('["Spoofing",               "100%", "72%", "24%"],',
     '["Spoofing",               "100%", "70%", "41%"],'),
    ('["Tampering",              "51%",  "8%",  "2%"],',
     '["Tampering",              "100%", "9%",  "3%"],'),
    ('["Repudiation",            "45%",  "9%",  "1%"],',
     '["Repudiation",            "100%", "9%",  "2%"],'),
    ('["Information Disclosure", "100%", "11%", "2%"],',
     '["Information Disclosure", "100%", "8%",  "3%"],'),
    ('["Denial of Service",      "100%", "10%", "1%"],',
     '["Denial of Service",      "100%", "9%",  "3%"],'),
    ('["Elevation of Privilege", "100%", "10%", "2%"],',
     '["Elevation of Privilege", "100%", "8%",  "3%"],'),
]

missing = []
for old, new in REPLACEMENTS:
    if old not in src:
        missing.append(old)
    else:
        src = src.replace(old, new)

if missing:
    print(f"WARNING: {len(missing)} old strings not found (already changed or mismatched):")
    for m in missing:
        print("  ", repr(m[:80]))
else:
    print(f"All {len(REPLACEMENTS)} replacements applied cleanly.")

open(PATH, "w").write(src)
