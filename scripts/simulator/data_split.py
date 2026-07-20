"""
Deterministic train/val/test split, shared between the model-training script
(scripts/train_dos_eop_classifiers.py) and the live simulator (enhanced_sim.py).

The split key is the row's own position in the file, hashed with MD5 (not a
random seed) so the training script and the simulator compute the identical
split independently. The live simulator is restricted to the "test" bucket
for these files, so no row a classifier trained or was tuned on can appear
in a live evaluation session.
"""
import hashlib

TRAIN_FRACTION = 0.6
VAL_FRACTION = 0.2
# remaining 0.2 is test

# Files a classifier is trained on.
SPLIT_FILES = {
    "02-14-2018.csv", "02-15-2018.csv", "02-22-2018.csv", "02-28-2018.csv",
}


def split_bucket(row_index: int) -> str:
    """train / val / test, deterministic by row position."""
    h = int(hashlib.md5(str(row_index).encode()).hexdigest(), 16) % 1000
    frac = h / 1000.0
    if frac < TRAIN_FRACTION:
        return "train"
    elif frac < TRAIN_FRACTION + VAL_FRACTION:
        return "val"
    return "test"


def is_split_file(filename: str) -> bool:
    import os
    return os.path.basename(filename) in SPLIT_FILES
