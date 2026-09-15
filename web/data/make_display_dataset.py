#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Build web/ui/transactions.json — the sample transactions the web UI offers.

Each entry pairs a human-readable rendering (amount, merchant, category, ...)
with the standardized 82-feature vector the client encrypts. The truth label
rides along so the UI can reveal model-vs-truth after scoring; it is never sent
to the server.

The source CSV defaults to data/stream_1k.csv (~10% fraud — the deliberate demo
compression; real traffic is ~0.5%). Regenerate the source mix itself with
data/make_workload_dataset.py --fraud-pct N.

Usage: python3 make_display_dataset.py [--csv PATH] [--rows N] [--out PATH]

Uses only the standard library.
"""
import argparse
import csv
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

DOW = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def pretty_category(slug: str) -> str:
    names = {
        "entertainment": "Entertainment", "food_dining": "Food & Dining",
        "gas_transport": "Gas & Transport", "grocery_net": "Grocery (online)",
        "grocery_pos": "Grocery (in store)", "health_fitness": "Health & Fitness",
        "home": "Home", "kids_pets": "Kids & Pets", "misc_net": "Misc (online)",
        "misc_pos": "Misc (in store)", "personal_care": "Personal Care",
        "shopping_net": "Shopping (online)", "shopping_pos": "Shopping (in store)",
        "travel": "Travel",
    }
    return names.get(slug, slug)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(REPO / "data" / "stream_1k.csv"))
    ap.add_argument("--rows", type=int, default=None, help="cap the row count")
    ap.add_argument("--out", default=str(REPO / "web" / "ui" / "transactions.json"))
    args = ap.parse_args()

    meta = json.loads((HERE / "encoding_meta.json").read_text())
    cols = meta["columns"]
    mean = dict(zip(cols, meta["mean"]))
    scale = dict(zip(cols, meta["scale"]))
    inv_merchant = meta["ordinal_inverse"]["merchant"]
    inv_first = meta["ordinal_inverse"]["first"]
    inv_last = meta["ordinal_inverse"]["last"]
    inv_city = meta["ordinal_inverse"]["city"]
    inv_job = meta["ordinal_inverse"]["job"]

    with open(args.csv, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        assert header[1:] == cols, "CSV feature columns do not match encoding_meta"
        rows = list(reader)
    if args.rows:
        rows = rows[: args.rows]

    def unz(name: str, raw: dict) -> float:
        return raw[name] * scale[name] + mean[name]

    out_rows = []
    n_fraud = 0
    for i, row in enumerate(rows):
        label = int(float(row[0]))
        n_fraud += label
        feats = [float(x) for x in row[1:]]
        raw = dict(zip(cols, feats))

        def ordinal(name: str, table: dict) -> str:
            return table.get(str(int(round(unz(name, raw)))), "?")

        category = next(
            (c[len("category_"):] for c in cols
             if c.startswith("category_") and round(unz(c, raw)) == 1),
            "entertainment",  # drop_first: all-zero one-hots mean the first category
        )
        state = next(
            (c[len("state_"):] for c in cols
             if c.startswith("state_") and round(unz(c, raw)) == 1),
            "AK",  # drop_first baseline
        )
        merchant = ordinal("merchant", inv_merchant)
        if merchant.startswith("fraud_"):  # Sparkov prefixes every merchant
            merchant = merchant[len("fraud_"):]

        out_rows.append({
            "id": i,
            "amount": round(unz("amt", raw), 2),
            "merchant": merchant,
            "category": pretty_category(category),
            "holder": f'{ordinal("first", inv_first)} {ordinal("last", inv_last)}',
            "gender": "M" if round(unz("gender_M", raw)) == 1 else "F",
            "age": int(round(unz("age", raw))),
            "job": ordinal("job", inv_job),
            "city": ordinal("city", inv_city),
            "state": state,
            "city_pop": int(round(unz("city_pop", raw))),
            "hour": int(round(unz("hour", raw))),
            "day_of_week": DOW[int(round(unz("day_of_week", raw))) % 7],
            "month": MONTHS[(int(round(unz("month", raw))) - 1) % 12],
            "truth": label,
            "features": feats,
        })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": Path(args.csv).name, "rows": out_rows}))
    print(f"wrote {out} — {len(out_rows)} rows, {n_fraud} fraud "
          f"({100 * n_fraud / len(out_rows):.1f}%), {out.stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    main()
