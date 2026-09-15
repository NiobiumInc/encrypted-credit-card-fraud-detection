#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""One-time extraction of the feature-encoding metadata used to render
human-readable transactions in the web UI.

The CSVs in data/ are z-score standardized, which is what the model consumes
but is unreadable in a table. The original StandardScaler and encoder mappings
live in the sibling fraud-challenge repository (same hardshell.ai lineage).
This script reads those pickles once and writes web/data/encoding_meta.json,
which is checked in so the web demo has no dependency on that repository or on
scikit-learn.

Usage: python3 extract_encoding_meta.py [path-to-fraud-challenge-repo]
"""
import json
import pickle
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

HERE = Path(__file__).resolve().parent
SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent.parent.parent / "fraud-challenge"

scaler = pickle.load(open(SRC / "scaler.pkl", "rb"))
cols = pickle.load(open(SRC / "feature_cols.pkl", "rb"))
mappings = json.load(open(SRC / "encoder_mappings.json"))

meta = {
    "columns": list(cols),
    "mean": [float(x) for x in scaler.mean_],
    "scale": [float(x) for x in scaler.scale_],
    # ordinal code -> original string, per ordinal-encoded column
    "ordinal_inverse": {
        col: {str(v): k for k, v in table.items()}
        for col, table in mappings["ordinal"].items()
    },
    "ohe": mappings["ohe"],
    "drop_first": mappings["drop_first"],
}

out = HERE / "encoding_meta.json"
out.write_text(json.dumps(meta))
print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")
