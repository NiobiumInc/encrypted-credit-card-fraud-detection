#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
make_workload_dataset.py - build the 1000-transaction anomaly-detection workload.

One master list; the harness workload sizes (single/small/medium/large = 1/20/50/100)
are nested PREFIXES of it. Fraud is the minority anomaly (~10%), sprinkled one per
10-row block so every size lands on an exact, known fraud count (1/2/5/10) and any
prefix is a mostly-normal stream with a few anomalies. Row 0 is a fraud so `single`
demonstrates a catch.

The ~10%% rate is a deliberate demo compression: real fraud is ~0.5% (see
--data realistic), too sparse to show detection in <=100 transactions. Fraud rows
come from test_rows_fraud_all.csv, legit rows from test_rows_5k.csv (same Sparkov
schema + global standardization — verified). Deterministic (fixed seed).

    python3 data/make_workload_dataset.py                    # 1000 rows, 10% fraud
    python3 data/make_workload_dataset.py --total 1000 --fraud-pct 5
"""
import argparse
import csv
import random
from pathlib import Path

HERE = Path(__file__).resolve().parent


def read_csv(path):
    with path.open() as f:
        rows = [r for r in csv.reader(f) if r]
    return rows[0], rows[1:]


def is_label(cell, want):
    try:
        return int(float(cell)) == want
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(description="Build the anomaly-detection workload list.")
    ap.add_argument("--total", type=int, default=1000, help="total transactions (default 1000)")
    ap.add_argument("--fraud-pct", type=float, default=10.0, help="fraud percentage (default 10)")
    ap.add_argument("--seed", type=int, default=42, help="shuffle seed (default 42)")
    ap.add_argument("--fraud-src", type=Path, default=HERE / "test_rows_fraud_all.csv")
    ap.add_argument("--legit-src", type=Path, default=HERE / "test_rows_5k.csv")
    ap.add_argument("--out", type=Path, default=HERE / "stream_1k.csv")
    args = ap.parse_args()

    _, fraud_rows = read_csv(args.fraud_src)
    legit_hdr, legit_rows = read_csv(args.legit_src)
    header = ["is_fraud"] + legit_hdr[1:]   # identical feature schema; normalize col 0

    fraud = [r for r in fraud_rows if is_label(r[0], 1)]
    legit = [r for r in legit_rows if is_label(r[0], 0)]

    n_fraud = round(args.total * args.fraud_pct / 100.0)
    if n_fraud < 1 or n_fraud > args.total:
        raise SystemExit(f"error: fraud-pct {args.fraud_pct} gives {n_fraud} fraud of {args.total}")
    block = args.total // n_fraud            # spread 1 fraud per block => even, known prefixes
    n_legit = args.total - n_fraud
    if len(fraud) < n_fraud or len(legit) < n_legit:
        raise SystemExit(f"error: need {n_fraud} fraud + {n_legit} legit; "
                         f"have fraud={len(fraud)} legit={len(legit)}")

    rng = random.Random(args.seed)
    rng.shuffle(fraud)
    rng.shuffle(legit)

    rows, li = [], 0
    for b in range(n_fraud):
        chunk = legit[li:li + (block - 1)]   # block-1 legit
        li += block - 1
        pos = 0 if b == 0 else rng.randrange(block)   # block 0 fraud at row 0 (single = a catch)
        chunk = list(chunk)
        chunk.insert(pos, fraud[b])
        rows.extend(chunk)
    rows.extend(legit[li:li + (args.total - len(rows))])   # top up any remainder with legit

    with args.out.open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)

    nf = sum(1 for r in rows if is_label(r[0], 1))
    print(f"wrote {args.out.name}: {len(rows)} rows ({nf} fraud / {len(rows) - nf} legit, "
          f"{100.0*nf/len(rows):.0f}%), 1 fraud / {block}-row block, seed={args.seed}")
    for n in (1, 20, 50, 100):
        fn = sum(1 for r in rows[:n] if is_label(r[0], 1))
        print(f"  first {n:>4} rows -> {fn} fraud")


if __name__ == "__main__":
    main()
