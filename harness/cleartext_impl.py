#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
cleartext_impl.py — plaintext reference for the credit card fraud detection MLP.

The SAME model the FHE circuit evaluates, but in the clear: no encryption, no
CKKS, no Niobium. Read this first to understand what the encrypted server does
on your behalf — then run the FHE pipeline (harness/run_submission.py) and watch
the SAME two logits come out of ciphertexts, except the server never sees the
transaction features in the clear.

The model is a fixed, pre-trained MLP:  82 -> 128 -> 64 -> 2 logits.
BatchNorm has been FOLDED into the linear weights, and between layers a degree-5
Chebyshev-polynomial approximation of ReLU is applied (bounded-domain, no
bootstrap). The prediction is argmax over the two logits: FRAUD iff
logit[1] > logit[0], otherwise legit/OK. Inputs are ALREADY standardized
(z-scored) features — they are not re-standardized here.

The weights below are lifted verbatim from the HEIR-generated kernel
src/fraud_model_lib.inc.cc (the `_assign_layout_*()` float literals) and the
activation is transcribed op-for-op from that kernel's Chebyshev arithmetic.
Every step maps to a stage of the FHE circuit:

  1. encode     features -> packed slot vector       (run_inference__encrypt__arg0)
  2. fc1 matvec W1 @ x + b1  (128 pre-acts)           (diagonal rotate-and-sum matvec)
  3. act        degree-5 Chebyshev ReLU, per neuron   (power-basis EvalMult chain)
  4. fc2 matvec W2 @ h1 + b2 (64 pre-acts)            (diagonal rotate-and-sum matvec)
  5. act        degree-5 Chebyshev ReLU, per neuron   (power-basis EvalMult chain)
  6. output     W3 @ h2 + b3 (2 logits)               (final rotate-sum to 2 slots)
  7. decode     argmax of the two logits              (run_inference__decrypt__result0)

In the FHE version every one of steps 2-6 is done homomorphically on ciphertexts:
the matvecs are diagonal rotate-and-sum, the activation is built from
plaintext-scaled EvalMult / EvalMultNoRelin power-basis multiplies, and only the
final two logits are ever decrypted. Here the arithmetic is exact; the FHE
version lands within CKKS approximation error of these same numbers.

    python3 harness/cleartext_impl.py 0                     # single txn, stream row 0
    python3 harness/cleartext_impl.py 1 --row 19            # stream row 19
    python3 harness/cleartext_impl.py 1 --data balanced --row 0
"""
import argparse
import csv
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from params import (InstanceParams, DATASETS, DEFAULT_DATASET, SINGLE, MEDIUM,
                    instance_name, MODEL_SHAPE)

ROOT = Path(__file__).resolve().parent.parent

# ── Where the weights live: the HEIR-generated kernel ────────────────────────
# The 6 baked weight/bias arrays are `std::vector<float> v0 = {...}` literals in
# the `_assign_layout_*()` functions near the top of the kernel. We parse them
# straight out of the .cc so the weights here cannot drift from what the circuit
# evaluates, identifying each by its element count AND its position in file order
# (two arrays are 128-long — output weight then fc1 bias — so count alone is
# ambiguous). The activation below is a different matter: its constants are
# copied, not parsed, so a change to the kernel's Chebyshev arithmetic would have
# to be mirrored here by hand.
KERNEL = ROOT / "src" / "fraud_model_lib.inc.cc"

N_IN, N_H1, N_H2, N_OUT = 82, 128, 64, 2          # 82 -> 128 -> 64 -> 2

# The `_assign_layout_*()` functions appear in this fixed order in the kernel.
# (name, element count) — the pair disambiguates the two 128-element arrays.
_LAYOUT_ORDER = [
    ("b3", N_OUT),            # 2     output bias   {-1.47049, 1.45693}
    ("W3", N_OUT * N_H2),     # 128   output weight (2 x 64), first row ~{0.1505, 3.087, ...}
    ("b2", N_H2),             # 64    fc2 bias
    ("W2", N_H2 * N_H1),      # 8192  fc2 weight (64 x 128)
    ("b1", N_H1),             # 128   fc1 bias      ~{-1.1818, 1.2644, ...}
    ("W1", N_H1 * N_IN),      # 10496 fc1 weight (128 x 82)
]

# ── Degree-5 Chebyshev ReLU, transcribed op-for-op from the kernel ───────────
# Kernel scalar constants (run_inference__preprocessing locals v0..v7). The FHE
# circuit multiplies the ciphertext by these plaintext constants; here they are
# ordinary floats. u = 0.1*x maps the pre-activation into Chebyshev's [-1,1]
# domain, then the approximation is assembled from the Chebyshev basis T2/T3/T4.
_DOMAIN_SCALE = 0.10000000149011612            # v0: pre-activation -> [-1, 1]
_C_LIN = 0.68831551074981689                   # v1: coeff on u
_C_T3 = -0.26905643939971924                   # v4: coeff on T3
_C_LIN2 = 0.17252917587757111                  # v5: coeff on u (in the *T4 term)
_C_T3_2 = -0.12523216009140015                 # v6: coeff on T3 (in the *T4 term)
_C_BIAS = 0.5                                  # v7: additive 0.5 (ReLU offset)


def cheby_relu(x):
    """Degree-5 Chebyshev approximation of ReLU (the kernel's activation).

    Op-for-op mirror of run_inference__preprocessed lines ~9265-9310:
        u  = 0.1 * x
        T2 = 2*u*u - 1                 (ct287: 2u*u - 1)
        T3 = 4*u**3 - 3*u              (ct293: (2u)*T2 - u)
        T4 = 2*T2*T2 - 1               (ct311: (2*T2)*T2 - 1)
        act = 0.5 + 0.68831551*u - 0.26905644*T3
                  + (0.17252918*u - 0.12523216*T3) * T4
    In the FHE version this whole chain runs homomorphically on the ciphertext,
    one activation per hidden neuron in its own slot.
    """
    u = _DOMAIN_SCALE * x
    t2 = 2.0 * u * u - 1.0
    t3 = 4.0 * u ** 3 - 3.0 * u
    t4 = 2.0 * t2 * t2 - 1.0
    return (_C_BIAS + _C_LIN * u + _C_T3 * t3
            + (_C_LIN2 * u + _C_T3_2 * t3) * t4)


# ── Weight loading ───────────────────────────────────────────────────────────
def _parse_float_literals(kernel_path):
    """Pull the `_assign_layout_*` float literals out of the kernel IN FILE ORDER,
    then bind them to (name -> values) via _LAYOUT_ORDER. Order + count together
    identify each array (count alone is ambiguous: b1 and W3 are both 128-long).
    """
    text = kernel_path.read_text()
    literals = []
    for m in re.finditer(r"_assign_layout_\d+\(\)\s*\{\s*"
                         r"std::vector<float>\s+v0\s*=\s*\{([^}]*)\}", text):
        literals.append([float(x) for x in m.group(1).split(",") if x.strip()])
    if len(literals) < len(_LAYOUT_ORDER):
        raise RuntimeError(
            f"Expected >= {len(_LAYOUT_ORDER)} weight literals in {kernel_path}, "
            f"found {len(literals)}")
    named = {}
    for (name, count), vals in zip(_LAYOUT_ORDER, literals):
        if len(vals) != count:
            raise RuntimeError(
                f"{name}: expected {count} floats in kernel literal, got {len(vals)} "
                f"(kernel layout changed?)")
        named[name] = vals
    return named


def _reshape(raw, nout, nin):
    """Dense matrix from the flat literal. W[out=i][in=j] = raw[j + nin*i]."""
    return [[raw[j + nin * i] for j in range(nin)] for i in range(nout)]


def load_model(kernel_path=KERNEL):
    """Return (W1, b1, W2, b2, W3, b3) reconstructed from the kernel literals."""
    lit = _parse_float_literals(kernel_path)
    W1 = _reshape(lit["W1"], N_H1, N_IN)      # 128 x 82
    W2 = _reshape(lit["W2"], N_H2, N_H1)      # 64  x 128
    W3 = _reshape(lit["W3"], N_OUT, N_H2)     # 2   x 64
    return W1, lit["b1"], W2, lit["b2"], W3, lit["b3"]


# ── The MLP, in the clear ────────────────────────────────────────────────────
def _matvec(W, x, b):
    """W @ x + b. In the FHE version this is a diagonal rotate-and-sum matvec."""
    return [sum(W[i][j] * x[j] for j in range(len(x))) + b[i]
            for i in range(len(W))]


def run(features, model=None):
    """Forward pass. Returns (logits, trace) where trace holds intermediates.

    logits[0] = "legit" score, logits[1] = "fraud" score; predict FRAUD iff
    logits[1] > logits[0] (argmax), matching run_inference__decrypt__result0.
    """
    if model is None:
        model = load_model()
    W1, b1, W2, b2, W3, b3 = model

    z1 = _matvec(W1, features, b1)          # 2. fc1 matvec (128 pre-acts)
    h1 = [cheby_relu(v) for v in z1]        # 3. activation
    z2 = _matvec(W2, h1, b2)                # 4. fc2 matvec (64 pre-acts)
    h2 = [cheby_relu(v) for v in z2]        # 5. activation
    logits = _matvec(W3, h2, b3)            # 6. output (2 logits)

    trace = {"z1": z1, "h1": h1, "z2": z2, "h2": h2, "logits": logits}
    return logits, trace


def is_fraud(logits):
    """argmax over the two logits: FRAUD iff logit[1] > logit[0]."""
    return logits[1] > logits[0]


# ── CSV: mirror src/fraud_bench_common.h read_csv (label, then 82 features) ──
def read_features(csv_path, row):
    """Row `row` (0-based, after the header): col 0 = label, cols 1..82 = the
    already-standardized features."""
    with open(csv_path, newline="") as f:
        rows = list(csv.reader(f))
    data = rows[1:]                         # skip header
    if row < 0 or row >= len(data):
        raise IndexError(f"row {row} out of range (dataset has {len(data)} rows)")
    line = data[row]
    label = int(float(line[0]))
    features = [float(x) for x in line[1:1 + N_IN]]
    if len(features) != N_IN:
        raise ValueError(f"row {row}: expected {N_IN} features, got {len(features)}")
    return label, features


def main():
    p = argparse.ArgumentParser(
        description="Plaintext reference for the credit card fraud detection MLP "
                    f"({MODEL_SHAPE}, degree-5 Chebyshev ReLU).")
    p.add_argument("size", type=int, choices=range(SINGLE, MEDIUM + 1),
                   help="Instance size (0=single, 1=small, 2=medium, 3=large)")
    p.add_argument("--data", default=DEFAULT_DATASET, choices=list(DATASETS),
                   help=f"evaluation dataset (default: {DEFAULT_DATASET})")
    p.add_argument("--row", type=int, default=0,
                   help="row index (0-based, after the header) to classify")
    args = p.parse_args()

    params = InstanceParams(args.size, args.data, ROOT)
    csv_path = params.get_csv()
    label, features = read_features(csv_path, args.row)

    model = load_model()
    logits, tr = run(features, model)
    fraud = is_fraud(logits)

    print(f"\n=== plaintext fraud detection ({instance_name(args.size)}, "
          f"data={args.data}) ===")
    print(f"model        : MLP {MODEL_SHAPE}, degree-5 Chebyshev ReLU "
          f"(BatchNorm folded)")
    print(f"dataset      : {csv_path.name}  (row {args.row}, "
          f"truth={'FRAUD' if label else 'OK'})")
    print(f"1. encode    : {len(features)} standardized features "
          f"-> packed slot vector")
    print(f"2. fc1 matvec: W1(128x82) @ x + b1  -> 128 pre-activations "
          f"(range [{min(tr['z1']):.2f}, {max(tr['z1']):.2f}])")
    print(f"3. act       : degree-5 Chebyshev ReLU  -> 128 h1 "
          f"(range [{min(tr['h1']):.2f}, {max(tr['h1']):.2f}])")
    print(f"4. fc2 matvec: W2(64x128) @ h1 + b2 -> 64 pre-activations "
          f"(range [{min(tr['z2']):.2f}, {max(tr['z2']):.2f}])")
    print(f"5. act       : degree-5 Chebyshev ReLU  -> 64 h2 "
          f"(range [{min(tr['h2']):.2f}, {max(tr['h2']):.2f}])")
    print(f"6. output    : W3(2x64) @ h2 + b3   -> logits = "
          f"({logits[0]:.4f}, {logits[1]:.4f})")
    print(f"7. decode    : argmax(logit0={logits[0]:.4f}, logit1={logits[1]:.4f}) "
          f"= slot {1 if fraud else 0}")

    verdict = "FRAUD" if fraud else "legit"
    score = logits[1] - logits[0]           # anomaly score = logit1 - logit0
    print(f"\nVERDICT: {verdict}  (fraud iff logit1 > logit0; "
          f"score = logit1-logit0 = {score:+.4f})")
    print("\nThe FHE pipeline computes these SAME two logits on encrypted data —\n"
          "the server never sees the transaction features. Try it:\n"
          f"    python3 harness/run_submission.py {args.size} "
          f"--data {args.data} --row {args.row}")
    return 0


if __name__ == "__main__":
    sys.exit(main())