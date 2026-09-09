# Encrypted Credit Card Fraud Detection

Score a card transaction for fraud without the scoring party ever seeing it.

This demo runs a trained neural network under fully homomorphic encryption with
OpenFHE. The client encrypts one transaction and sends it to the server, which
evaluates the model on ciphertext it cannot read and returns an encrypted verdict.
Only the client can decrypt it.

The server holds the model and the evaluation keys, and never receives the secret
key. The compute stage runs on a Niobium FPGA over the Fog, so no local
accelerator is needed.

The decrypted result matches the cleartext model to within CKKS approximation
error, and every run is checked against a plaintext reference.

The transaction and the verdict stay confidential throughout, while the model is
disclosed to whoever evaluates the circuit. [Trust boundary](#trust-boundary) sets
out who sees what.

## Run it

Prerequisites: a C++17 compiler, CMake 3.16.3 or newer, Python 3, and about 6 GB
of RAM. The harness uses only the standard library.

Fog access is gated. Request an account at
[console.niobium.co/request-account](https://console.niobium.co/request-account).

```bash
# one-time setup: builds OpenFHE, libnbfhetch and the four stages
git submodule update --init niobium-client
./scripts/build_task.sh

# authenticate once, then score one transaction on a real FPGA over the Fog.
# The harness leases a worker per transaction.
niobium-client/scripts/fog login -u you@example.com
python3 harness/run_submission.py 0 --target FOG

# the same transaction in software, as a check on the hardware result
python3 harness/run_submission.py 0

# 20 transactions, in software.
python3 harness/run_submission.py 2
```

`python3 harness/cleartext_impl.py 0` runs the same forward pass in the clear,
on a fresh clone with nothing built. It prints the two scores and the verdict,
annotating each step with the FHE stage it corresponds to.

## What happened

Four binaries ran in order, split across the client/server boundary. The two
sides are separate processes that exchange only ciphertexts and public material.

| Stage | Binary | Runs on | Produces |
|---|---|---|---|
| 1 | `fraud_client_keygen` | client | crypto context, public, secret, and evaluation keys |
| 2 | `fraud_client_encrypt` | client | the encrypted transaction |
| 3 | `fraud_server_sdk` | server | the two encrypted scores |
| 4 | `fraud_client_decrypt` | client | the scores and a fraud verdict; appends `results.csv` |

Each stage takes `--help`, which describes it and names the arguments the harness
passes, so a stage can be re-run by hand.

This model's weights are compiled into the kernel and travel with the trace, so
the compute stage carries the model to the backend. [Trust boundary](#trust-boundary)
covers what that discloses.

Stage 3 is the one that uses Niobium. It records the circuit once, then replays
it on the backend `--target` chooses; every transaction runs that identical
circuit, so one recording serves them all and only the ciphertext changes.

The model is a small tabular multi-layer perceptron, `82 -> 128 -> 64 -> 2`,
mapping 82 standardized transaction features to two scores, one for legitimate and
one for fraudulent. The larger score is the verdict.

They are raw outputs of the final layer, and comparing them is enough for a
verdict, so the circuit ends there. Machine-learning writing calls them logits,
which is the name the code uses.

Each layer becomes CKKS arithmetic: rotations and plaintext multiplies for the
linear maps, and a degree-5 Chebyshev polynomial in place of ReLU. The whole
forward pass fits inside one level budget, and
[docs/DESIGN.md](docs/DESIGN.md) §3 has the construction.

The client decrypts both scores and takes the gap between them as the anomaly
score. The model is a fixed demo fixture, retrained so its activations stay in the
range a polynomial can approximate. Every run checks the decrypted scores
against the same forward pass in the clear — see [Checking the
answer](#checking-the-answer).

```console
$ python3 harness/run_submission.py 0 --target FOG

[harness] fraud detection: 1 transaction(s) from 'stream' (1000-txn anomaly stream, ~10% fraud sprinkled (default); sizes are prefixes)
[harness] model 82->128->64->2, ring 2^16, depth 15  |  size=single
[harness] backend: Niobium over transport (FOG), O3
[harness] Fog jobs: one per transaction, wrapping the compute stage

=== row 0 ===
[fog] assigned b0cfcde0 -> https://dal1-fog-lb-01.nio41.co/.../run
[server-sdk] ring=65536 primes=16 row=0
[server-sdk] recording trace for row 0 ...
[server-sdk] record done, trace only
[fog] upload 5095/5095 MB (100%)
[fog] upload complete — replaying on target FOG, waiting for the server
[server-sdk] replay done
Row    0  truth=FRAUD  pred=FRAUD  L[0]=-4.6705  L[1]=4.7053  [agree]

=== summary ===
transactions: 1 from 'stream' (1000-txn set, 10% fraud)
computed on:  a real Niobium FPGA, as a job on the Fog (--target FOG)
reference:    1/1 rows match the plaintext reference   (max logit deviation 6.65e-07, tol 0.05)

Done. Every transaction above agreed with the plaintext reference.
```

Those lines are a real run. A full run prints around a thousand: the recorder
and the transport both log heavily, and the upload counts its way up to the
figure shown.

The transport is stateless, so every request carries the evaluation keys and the
model alongside the transaction, which is why the Fog example scores one and the
twenty-transaction run stays in software.

`--target local` puts the same circuit through an in-process simulator and returns
the same scores.

## More information

- [docs/DESIGN.md](docs/DESIGN.md): the model, the homomorphic evaluation, the
  depth budget and the threat model.
- [docs/NIOBIUM_CLIENT_TRANSPORT.md](docs/NIOBIUM_CLIENT_TRANSPORT.md): the
  record, ship and replay flow, and what the backend receives.
- [data/README.md](data/README.md): dataset provenance and the regeneration
  script.
- [Trust boundary](#trust-boundary): who sees the transaction, and who sees the model.
- [Security and parameters](#security-and-parameters): the CKKS configuration.
- [Repository layout](#repository-layout): where the code lives.

### Sizes and datasets

The size argument selects how many transactions are classified. The crypto
parameters are the same for every size.

| Size | Transactions |
|---|---|
| `0` single | 1 |
| `1` small | 5 |
| `2` medium | 20 |

Every size runs on the Fog, one job per transaction.

Each transaction ships the evaluation keys and the model alongside itself, so
budget about 5 GB for each. On a slow link a transfer can outlast the job's
time limit; re-run the transaction if that happens.

`--rows N` overrides the size's count.

The transactions are synthetic, generated with the Sparkov simulator, and the
features are already standardized. `--data` selects the evaluation set, capped to
its row count:

| `--data` | rows | fraud rate | role |
|---|---|---|---|
| `stream` (default) | 1000 | ~10% | anomaly-detection stream; sizes are prefixes |
| `balanced` | 20 | 50% | quick correctness set; hardest for the model |
| `realistic` | 5000 | ~0.5% | true base rate |
| `fraud` | 9651 | 100% | all-fraud set |

Full provenance and the regeneration script are in
[`data/README.md`](data/README.md).

### Checking the answer

`harness/cleartext_impl.py` recomputes the same forward pass in the clear, and
the harness compares every decrypted transaction against it. A verdict that
disagrees fails the run.

`--reference-tol` sets how far the scores may deviate before that counts as a
failure; the default of 0.05 sits four orders of magnitude above the deviation
measured on real runs, which is around 1e-06.

### Trust boundary

The transaction and the verdict stay confidential throughout. The model is the
exposed part: its weights are CKKS *plaintext*, which is what keeps the circuit
cheap, and whatever machine evaluates the circuit can read them.

Running the compute stage on a remote accelerator therefore discloses the model to
that accelerator's operator, and [docs/DESIGN.md](docs/DESIGN.md) §5 sets this out
in full.

In this demo the weights are literals in `src/fraud_model_lib.inc.cc`, so they are
public and `harness/cleartext_impl.py` reads them back to build its reference. In
a deployment they would be the server's own secret.

### Security and parameters

| Parameter | Value |
|---|---|
| Scheme | CKKS, `FIXEDMANUAL` rescaling |
| Ring dimension | 2^16 |
| Multiplicative depth | 15 |
| Security | `HEStd_128_classic` (128-bit classical) |
| Bootstrapping | none |

The depth of 15 covers two hidden layers, each a linear map followed by the
degree-5 Chebyshev activation, plus the output layer, which is what fits the whole
forward pass into one level budget. OpenFHE sizes the modulus chain so
`logQ` stays inside the [Homomorphic Encryption Standard](https://homomorphicencryption.org)
bound for `N = 2^16`, giving at least 128 bits of classical security.

The OpenFHE `CCParams`, from the generated kernel in
[src/fraud_model_lib.inc.cc](src/fraud_model_lib.inc.cc):

```cpp
CCParamsT params;
params.SetMultiplicativeDepth(15);          // two hidden layers + output
params.SetScalingTechnique(FIXEDMANUAL);    // the kernel inserts its own rescales
params.SetRingDim(65536);                   // N = 2^16
params.SetSecurityLevel(HEStd_128_classic);
params.SetKeySwitchTechnique(HYBRID);
```

CKKS is approximate arithmetic, so a decrypted result carries approximation
error; that is what the tolerance above absorbs.

[docs/DESIGN.md](docs/DESIGN.md) has the full depth accounting and threat model.

### Backends

| `--target` | Where the replay runs |
|---|---|
| `local` (default) | in-process, through the simulator the client bundles. Use it to check a hardware result. |
| `FOG` | a real Niobium FPGA, as a job on the Fog. |

`FOG` is a stable alias: the server resolves it to its pinned device, so a client
names the target and leaves the device to the Fog.
[docs/NIOBIUM_CLIENT_TRANSPORT.md](docs/NIOBIUM_CLIENT_TRANSPORT.md) describes the
record, ship and replay flow.

The `niobium-client` submodule supplies OpenFHE as well as the transport, and its
pin records the commit the app is built and validated against. Recording a
computation relies on hooks carried by that fork, which is why the build uses it.

### Repository layout

```
.
├── harness/
│   ├── run_submission.py             # the entry point
│   ├── cleartext_impl.py             # the plaintext reference
│   └── params.py                     # sizes and dataset selection
├── scripts/
│   └── build_task.sh                 # builds the client, then the stages
├── src/
│   ├── fraud_client_keygen.cc        # stage 1
│   ├── fraud_client_encrypt.cc       # stage 2
│   ├── fraud_server_compute_sdk.cc   # stage 3
│   ├── fraud_client_decrypt.cc       # stage 4
│   └── fraud_model_lib.inc.cc        # the generated model kernel
├── data/                             # synthetic transactions and provenance
├── docs/                             # DESIGN.md, NIOBIUM_CLIENT_TRANSPORT.md
├── LICENSE.md                        # Apache-2.0
└── niobium-client/                   # submodule: OpenFHE, libnbfhetch, transport
```

`io/`, `measurements/` and a `fraud-inference_*/` trace cache are created at
runtime and hold the files the stages exchange, the per-run metrics, and the
recorded program the backend replays.

## Acknowledgements

Built with [hardshell.ai](https://hardshell.ai) and Google, who describe the
collaboration in
[a post on private AI](https://blog.google/security/how-google-is-making-private-ai-practical-with-homomorphic-encryption/).

The original model and dataset came from hardshell.ai, and Google's
[HEIR](https://github.com/google/heir) toolchain lowers the PyTorch model to an
OpenFHE CKKS circuit. Niobium rebuilt the model to run under FHE, retraining the
network so its activations stay in the range a polynomial can approximate.

The transactions come from the
[Sparkov](https://github.com/namebrandon/Sparkov_Data_Generation) simulator, and
the FHE library is [OpenFHE](https://github.com/openfheorg/openfhe-development).
