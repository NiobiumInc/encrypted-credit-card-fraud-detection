# Design — encrypted fraud-detection MLP

This document describes the model, how it is evaluated homomorphically, and the
crypto parameters and their security/depth rationale. For build & run see the
[README](../README.md); for the Niobium transport see
[NIOBIUM_CLIENT_TRANSPORT.md](NIOBIUM_CLIENT_TRANSPORT.md).

## 1. Problem

Given a single card transaction described by 82 numeric features, decide whether
it is **fraudulent** or **legitimate**. Fraud is rare (well under 1% of real
traffic), so in practice this is an **anomaly detector**: the model produces a
score that separates the occasional fraudulent transaction from a stream of normal
ones, and a threshold turns that score into a decision. The privacy goal is that
the party running the model (a bank or processor) learns the verdict **without
seeing the transaction in the clear**.

## 2. Model

A fixed, pre-trained tabular **multi-layer perceptron**:

```
input (82)
  → Linear(82 → 128) + BatchNorm → ϕ
  → Linear(128 → 64) + BatchNorm → ϕ
  → Linear(64 → 2)                        → 2 logits
```

- **ϕ** is a **degree-5 Chebyshev polynomial approximation of ReLU**. Exact ReLU
  (`max(0,x)`) is not an arithmetic circuit, so it is replaced by a low-degree
  polynomial that CKKS can evaluate. This approximation — not FHE noise — is the
  main source of any difference between the encrypted model and the ideal
  plaintext ReLU network.
- The two outputs are the *legitimate* and *fraudulent* logits; the prediction is
  their `argmax`, and the **anomaly score** is `logit_fraud − logit_legit`.
- **BatchNorm** is what holds each stage's activations inside the interval ϕ is
  fitted over, which is why the network is trained with it at every stage. At
  inference it is an affine map, folded into the adjacent linear layer's weights
  and biases, so the deployed circuit evaluates it for free.

**Provenance.** The network was retrained for this circuit. A Chebyshev
approximation is only accurate over the interval it is fitted to, so the
activation inputs have to stay inside a known range; the original model did not
normalize strongly enough at each stage to guarantee that. Retraining with strong
per-stage normalization puts those range limits in place, which is what lets a
degree-5 polynomial stand in for ReLU across the whole network. Google's
[cc_fraud demo](https://github.com/google/fully-homomorphic-encryption/tree/main/demos/cc_fraud)
uses sigmoid activations and a different network. It carries the same feature
pipeline and 20-row fixture, which reached both projects from hardshell.ai.

It is trained in PyTorch and lowered to a CKKS circuit by
[Google HEIR](https://github.com/google/heir), targeting the OpenFHE 1.4 API.
It builds and runs against the OpenFHE the `niobium-client` submodule vendors,
which is 1.5.1 at the pin this repository carries. The trained weights
are baked into the generated kernel (`src/fraud_model_lib.inc.cc`); this repository
runs inference only. A pure-Python reconstruction of the same forward pass lives in
[`harness/cleartext_impl.py`](../harness/cleartext_impl.py) as the "understand it
first" reference.

## 3. Homomorphic evaluation

The features and all intermediate activations are packed into CKKS SIMD slots. Each
layer maps to standard CKKS operations:

- **Linear (`Wx + b`)** — a homomorphic matrix–vector product by the **diagonal /
  baby-step–giant-step** method: the packed input is rotated, each rotation is
  multiplied by a plaintext diagonal of `W`, and the products are summed
  (rotate-and-add). The bias is added as a plaintext. The weight diagonals and
  bias are the baked plaintexts produced by the kernel's preprocessing step.
- **Activation ϕ** — the degree-5 polynomial is evaluated on ciphertexts with a
  short chain of ciphertext×ciphertext multiplications (power basis) combined with
  the baked polynomial-coefficient plaintexts.
- **Output** — after the final linear layer, a rotate-and-sum reduction collapses
  the packed lanes into the two logit slots, which the client decrypts.

Only ciphertext×plaintext multiplications, ciphertext×ciphertext multiplications
(for the activation), rotations, and additions are used — **no bootstrapping**.

## 4. Crypto parameters and depth budget

The configuration is CKKS at ring dimension `N = 2^16` and multiplicative
depth 15, with `FIXEDMANUAL` rescaling and no bootstrapping; the
[README](../README.md#security-and-parameters) lists it in full alongside the
`CCParams` the kernel generates.

**Depth accounting.** The budget of 15 multiplicative levels covers the two
hidden layers (each a linear map followed by the degree-5 activation) and the
output linear layer, with the activation's polynomial evaluation dominating the
per-block depth. Because the whole forward pass fits in a single level budget, no
bootstrapping is required — the entire inference is one leveled computation.

`FIXEDMANUAL` rescaling means the circuit manages the CKKS scale explicitly (the
generated kernel inserts the rescales), which keeps the scale consistent across the
diagonal-matvec and polynomial-activation blocks.

## 5. Security

The scheme targets **128-bit classical security** (`HEStd_128_classic`). For a
depth-15 CKKS circuit, OpenFHE's parameter selection requires ring dimension
`N = 2^16` and sizes the RNS modulus chain accordingly; smaller rings cannot carry
this depth at 128-bit security. All key material (public, relinearization, and
rotation keys) is generated client-side; the server receives only the evaluation
keys it needs and the encrypted transaction, and never holds the secret key.

**Outsourced evaluation.** The analysis above has exactly two parties and assumes
the server evaluates the circuit itself. If the server instead offloads evaluation
to a remote accelerator, that accelerator receives the same material the server
would hold locally: the encrypted transaction, the evaluation keys, and the baked
weight plaintexts of §3. Transaction confidentiality is unaffected — the secret
key never leaves the client, and the accelerator handles only ciphertext for the
input and the result. What changes is that the model is disclosed to the
accelerator's operator, so offloading extends the server's own trust boundary
rather than preserving it. Treat a remote evaluator as part of the server for the
purposes of this analysis, and choose one accordingly. See
[NIOBIUM_CLIENT_TRANSPORT.md](NIOBIUM_CLIENT_TRANSPORT.md) for the offloaded path
this repository ships.

This analysis describes a deployment. The weights in this repository are literals
in the generated kernel, so they are public here and
[`harness/cleartext_impl.py`](../harness/cleartext_impl.py) reads them back to
build its reference.

## 6. Data

Transactions are **synthetic**, generated with the
[Sparkov](https://github.com/namebrandon/Sparkov_Data_Generation) simulator (the
lineage of the public Kaggle "Credit Card Transactions Fraud Detection" dataset) —
there is **no real cardholder data**. The 82 features are already **standardized**
(z-scored on the source population), so a fraudulent transaction's larger amount,
for example, shows up as a feature several standard deviations from the mean. Full
provenance, the per-feature ranges, and the dataset-generation script are in
[`../data/README.md`](../data/README.md).

## 7. Decision and evaluation

The client decrypts two logits and computes the anomaly score
`s = logit_fraud − logit_legit`; a transaction is flagged as fraud when `s > 0`,
which reproduces the model's `argmax`.

Every decrypted row is checked against the same forward pass computed in the
clear ([`harness/cleartext_impl.py`](../harness/cleartext_impl.py)); a row whose
logits drift further than `--reference-tol` fails the run.
