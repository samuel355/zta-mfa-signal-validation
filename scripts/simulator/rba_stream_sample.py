#!/usr/bin/env python3
"""
Stream-samples the RBA dataset directly from the zip (never extracts the full
9GB CSV to disk — only ~12GB free was available at extraction time). Keeps
every row flagged as Is Attack IP or Is Account Takeover (the real ground
truth for the Spoofing STRIDE bucket), plus a reservoir sample of benign rows
for negative-class balance.

Download rba-dataset.zip first from https://doi.org/10.5281/zenodo.6782156
into datasets/rba/ (see updated/reference_material/citations_rba_dataset.md).
Output (data/rba/rba_sample.csv) is the actual file the simulator reads —
that small filtered sample is git-tracked; this raw zip and script's
intermediate output under datasets/ are not (too large).
"""
import csv
import os
import random
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ZIP_PATH = os.path.join(BASE_DIR, "datasets", "rba", "rba-dataset.zip")
OUT_PATH = os.path.join(BASE_DIR, "data", "rba", "rba_sample.csv")
# Attack rate turned out to be ~9-10% of all logins (far higher than the
# "rare" account-takeover assumption) — bounding both reservoirs keeps the
# output at a scale comparable to the CIC-IDS2018 sample already in use,
# rather than accumulating millions of rows in memory/disk.
ATTACK_RESERVOIR_SIZE = 8000
BENIGN_RESERVOIR_SIZE = 8000

proc = subprocess.Popen(
    ["unzip", "-p", ZIP_PATH, "rba-dataset.csv"],
    stdout=subprocess.PIPE, text=True, bufsize=1 << 20,
)

reader = csv.DictReader(proc.stdout)
fieldnames = reader.fieldnames

attack_reservoir = []
benign_reservoir = []
n_seen = 0
n_attack_seen = 0
n_benign_seen = 0

for row in reader:
    n_seen += 1
    is_attack = row.get("Is Attack IP") == "True" or row.get("Is Account Takeover") == "True"
    if is_attack:
        n_attack_seen += 1
        if len(attack_reservoir) < ATTACK_RESERVOIR_SIZE:
            attack_reservoir.append(row)
        else:
            j = random.randint(0, n_attack_seen - 1)
            if j < ATTACK_RESERVOIR_SIZE:
                attack_reservoir[j] = row
    else:
        n_benign_seen += 1
        if len(benign_reservoir) < BENIGN_RESERVOIR_SIZE:
            benign_reservoir.append(row)
        else:
            j = random.randint(0, n_benign_seen - 1)
            if j < BENIGN_RESERVOIR_SIZE:
                benign_reservoir[j] = row

    if n_seen % 2_000_000 == 0:
        print(f"[STREAM] {n_seen:,} rows scanned, {n_attack_seen:,} attack rows seen (reservoir full: {len(attack_reservoir) >= ATTACK_RESERVOIR_SIZE})", file=sys.stderr)

proc.wait()

print(f"[STREAM] Done. n_seen={n_seen:,} n_attack_seen={n_attack_seen:,} attack_sample={len(attack_reservoir):,} benign_sample={len(benign_reservoir):,}", file=sys.stderr)

with open(OUT_PATH, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(attack_reservoir)
    writer.writerows(benign_reservoir)

print(f"[STREAM] Wrote {OUT_PATH}", file=sys.stderr)
