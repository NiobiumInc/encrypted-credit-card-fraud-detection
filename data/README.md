# Datasets: provenance and license

The transaction data in this directory is **synthetic** (machine-generated). It
contains **no real cardholder information**: every "PII-looking" column
(`cc_num`, `first`, `last`, `street`, …) is a standardized float, not a raw
value, so nothing here is re-identifiable.

## Origin

The data descends from the **Sparkov** synthetic credit-card-transaction
generator (by Brandon Harris), the same lineage as the widely used Kaggle
*"Credit Card Transactions Fraud Detection Dataset"* (`kartik2112/fraud-detection`).
The feature schema is a fingerprint match — Sparkov's `cc_num, merchant, amt,
city_pop, job, merch_lat/long` plus its distinctive transaction categories
(`category_food_dining, category_gas_transport, category_grocery_pos, …`), one-hot
`state_*`/`gender_M`, and time features (`hour, day_of_week, month, age`) derived
from Sparkov's `trans_date_trans_time`/`dob`. The natural fraud rate of the
realistic sample (~0.5%) matches Sparkov's documented rate.

**Provenance chain:** Sparkov synthetic generator → the Kaggle distribution →
feature engineering (one-hot `category`/`state`/`gender`, derived time/age) →
global z-score standardization → the CSVs here.

The encoded dataset reached this project from hardshell.ai, along with the model
it was built for. The same files went on to Google during the collaboration, which
is why `test_rows.csv` is byte-identical to the copy in their
[cc_fraud demo](https://github.com/google/fully-homomorphic-encryption/tree/main/demos/cc_fraud).

- Generator: <https://github.com/namebrandon/Sparkov_Data_Generation>
- Public distribution: <https://www.kaggle.com/datasets/kartik2112/fraud-detection>

## License

- **Kaggle distribution** — **CC0 1.0 (public domain)**, confirmed against the
  dataset page's License field. This is what the CSVs here descend from, so no
  attribution is legally required for them.
- **Sparkov generator** — **MIT License, © 2016–2022 Brandon Harris** (verified).
  The generator is not shipped here; the data it produced is.

The data is synthetic, and CC0 permits free redistribution. Attribution to
Sparkov is kept as a courtesy, which is what the Kaggle uploader does: "I do not
own the simulator. I used the one used by Brandon Harris"

## The files

| file | rows | fraud rate | role |
|------|------|-----------|------|
| `stream_1k.csv` | 1000 | ~10% (100) | **default** — anomaly-detection workload; sizes are nested prefixes |
| `test_rows.csv` | 20 | 50% (10/10) | 20-row 50/50 quick correctness / QA set |
| `test_rows_5k.csv` | 5000 | ~0.5% | true anomaly operating point (natural base rate) |
| `test_rows_fraud_all.csv` | 9651 | 100% | all-fraud set |
| `repeat_row0_x50.csv` | 50 | — | one transaction ×50 (throughput/reproducibility bench) |
| `feature_bounds.csv` | 82 | — | per-feature standardized clamp range (numeric + one-hot) |

`stream_1k.csv` is **generated**, not hand-curated: `make_workload_dataset.py` draws
fraud rows from `test_rows_fraud_all.csv` and legit rows from `test_rows_5k.csv` and
sprinkles fraud one-per-10-row-block (so it reads like a mostly-normal transaction
stream with occasional anomalies), fixed-seed and deterministic. The workload sizes
are nested prefixes with exact fraud counts — single/small/medium = first
1/5/20 rows = 1/1/2 fraud; row 0 is a fraud so `single` shows a catch.
Regenerate or retune with:

```
python3 data/make_workload_dataset.py --total 1000 --fraud-pct 10
```

The **~10% rate is a deliberate demo compression**: real fraud is ~0.5%
(`test_rows_5k.csv`), too sparse to show detection in ≤100 transactions — use
`--data realistic` for the true rate. Combining sources is safe because all feature
CSVs share the **same 82-feature schema and the same global z-score standardization**
— verified by checking that one-hot columns (raw 0/1) map to identical standardized
values in both source files. Column 0 is the label (`is_fraud`; the all-fraud export
names it `label`). The raw feature sets are **disjoint** (no row overlap).

## Attribution

Synthetic data generated with the Sparkov Data Generation tool
(https://github.com/namebrandon/Sparkov_Data_Generation), MIT License,
© 2016–2022 Brandon Harris.
