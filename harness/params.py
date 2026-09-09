#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
params.py - Workload sizes and datasets for encrypted credit card fraud detection.

Fraud detection is a fixed trained MLP (82 -> 128 -> 64 -> 2, degree-5 Chebyshev
ReLU, no bootstrap). The crypto params are CONSTANT for every size (ring 2^16,
multiplicative depth 15, CKKS FIXEDMANUAL). There is NO database being searched,
so the ONLY workload knob is the NUMBER OF TRANSACTIONS classified.

TWO INDEPENDENT AXES (do not conflate them):
  * size / --rows  = HOW MANY transactions (the throughput knob).
  * --data         = WHICH evaluation set (see DATASETS below).
Keeping them separate means a run's result is comparable across sizes on a fixed
dataset, instead of shifting because the data changed underneath you.
"""
from pathlib import Path

# ── Datasets: pick with --data. The default (stream) is a 1000-transaction
#    anomaly-detection workload — mostly-normal with ~10% fraud sprinkled; the
#    workload sizes are nested PREFIXES of it. The other three are specialty sets. ──
STREAM = "stream"
BALANCED = "balanced"
REALISTIC = "realistic"
FRAUD = "fraud"

DATASETS = {
    STREAM:    {"csv": "data/stream_1k.csv",           "rows": 1000, "fraud_pct": 10.0,
                "desc": "1000-txn anomaly stream, ~10% fraud sprinkled (default); sizes are prefixes"},
    BALANCED:  {"csv": "data/test_rows.csv",           "rows": 20,   "fraud_pct": 50.0,
                "desc": "20-row 50/50 quick correctness / QA set"},
    REALISTIC: {"csv": "data/test_rows_5k.csv",         "rows": 5000, "fraud_pct": 0.5,
                "desc": "natural ~0.5% fraud rate (true anomaly operating point)"},
    FRAUD:     {"csv": "data/test_rows_fraud_all.csv",  "rows": 9651, "fraud_pct": 100.0,
                "desc": "all-fraud set (every transaction is fraudulent)"},
}
DEFAULT_DATASET = STREAM

# ── Size = number of transactions (queries). The ONLY throughput knob. ──
SINGLE = 0
SMALL = 1
MEDIUM = 2
# Transaction counts. Deliberately small:
# each transaction is an independent round trip to the backend, so a tier is
# priced in uploads, not just in wall time. At these sizes with rare fraud
# (~0.5%) you cannot sample at the true base rate either, so the test subsets
# are stratified (fraud guaranteed present). Use --rows N for a longer run.
_SIZE_ROWS = [1, 5, 20]              # capped to the chosen dataset's row count

# ── Fixed crypto (same for every size). ──
RING_DIM = 65536
MULT_DEPTH = 15
MODEL_SHAPE = "82->128->64->2"


def instance_name(size):
    """String name of the size."""
    names = ["single", "small", "medium"]
    if size < SINGLE or size > MEDIUM:
        return "unknown"
    return names[size]


class InstanceParams:
    """Parameters for a (size, dataset) pair. rootdir = the repo root."""

    def __init__(self, size, data=DEFAULT_DATASET, rootdir=None):
        if size < SINGLE or size > MEDIUM:
            raise ValueError("Invalid size (0=single/1=small/2=medium)")
        if data not in DATASETS:
            raise ValueError(f"Invalid dataset '{data}' (choose from {list(DATASETS)})")
        self.size = size
        self.data = data
        self.rootdir = Path(rootdir) if rootdir else Path.cwd()

    def get_csv(self):
        """Absolute path to this dataset's transaction CSV."""
        return self.rootdir / DATASETS[self.data]["csv"]

    def get_num_rows(self):
        """Rows to run: the size's target count, capped to the dataset."""
        return min(_SIZE_ROWS[self.size], DATASETS[self.data]["rows"])

    # Directory layout (keyed by dataset + size so runs don't clobber each other).
    def iodir(self):
        return self.rootdir / "io" / self.data / instance_name(self.size)

    def measuredir(self):
        return self.rootdir / "measurements" / self.data / instance_name(self.size)
