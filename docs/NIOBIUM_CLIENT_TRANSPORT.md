# Fraud detection over the niobium-client FHETCH transport

This document describes how the fraud-detection app runs its server-side
homomorphic evaluation **over the niobium-client FHETCH transport** — the
client-over-HTTP path for shipping a recorded trace to a remote backend. The server's
`replay()` is shipped over HTTP to a `nbcc_fhetch_replay_server`, which `--exec`s a
Niobium replay backend (a released SDK) and returns the result ciphertext.

## What the backend receives

Offloading sends the recorded project to the backend. That project carries the
encrypted transaction, the evaluation keys, and the model's baked weight
plaintexts — the same material the server holds when it evaluates locally.

The secret key is not part of it. Only the client stages read `sk.bin`, nothing
server-side decrypts, and the compute stage reads only `cc.bin`, `mk.bin` and
`rk.bin` from the shared io-dir — it never opens `sk.bin`. The transaction and
the decrypted verdict stay confidential from the backend.

The model is a different matter. Its weights are CKKS plaintext, so offloading
discloses them to whoever operates the backend. Running remotely extends the
server's trust boundary to include that operator; it does not preserve it. See
`docs/DESIGN.md` §5.

## Where the replay runs

| Target | Where the replay runs |
|--------|------------------------|
| `local` (default) | in-process, through the client's bundled `fhetch_sim` |
| `FOG` | **shipped over HTTP to the Fog worker's job endpoint → replay backend** |

The compute stage links the SDK's **`libnbfhetch`**, whose `replay()` dispatches
to `nbcc_fhetch_replay` and becomes the FHETCH transport when
`NBCC_FHETCH_SERVER` is set.

## The compute stage

`fraud_server_compute_sdk.cc` runs the MLP through the explicit niobium-fhetch API
(`capture_crypto_context` / `tag_input` / `tag_keys`); the hardware data format is
selected by the replay `--target`.

`fraud_server_sdk` records once, then replays:

- **cache miss** — records the trace in **hollow mode**, which skips the FHE math,
  and writes **no result**. It needs no backend, so on the Fog this pass runs on
  the client. Hollow is on only for the math: it is off while the weight
  plaintexts are tagged, and off again before `probe`/`stop`, which serialize
  values the skipped math never produced.
- **cache hit** — replays over the transport and writes the result.

The backend is therefore the only source of an answer. A first run against a
fresh cache records, then replays in the same invocation, and the decrypt reads
only what the replay wrote.

The model's weight plaintexts are tagged inline during the forward pass via the
`MAKE_PLAINTEXT` `pause`/`tag_input`/`resume` idiom, so that code is shared; the
SDK target compiles the kernel with the niobium-fhetch include path first (its
`niobium::compiler()` also resolves to the SDK).

The record pass runs single-threaded (`OMP_NUM_THREADS=1`). The replay pass runs a
fixed trace and is unaffected.

## Building (self-contained — no compiler checkout)

`scripts/build_task.sh` builds it the way a customer does: the `niobium-client`
submodule builds its OWN bundled OpenFHE + `libnbfhetch` + the transport
server/forwarder, and the fraud stages build against that (`-DNIOBIUM_SDK_BUILD=ON`).

```bash
git submodule update --init niobium-client
scripts/build_task.sh            # heavy the first time (compiles OpenFHE once)
```

It outputs the client stages + `fraud_server_sdk` in `build/`, plus the transport
**server** (`nbcc_fhetch_replay_server`) and **forwarder** (`nbcc_fhetch_replay`)
under `niobium-client/build/src/fhetch_transport/`, and `libnbfhetch` under
`niobium-client/build/{vendor/niobium-fhetch,_deps/niobium-fhetch-build}`.

## Running it

`harness/run_submission.py` records the trace, replays it over the transport and
decrypts, in one command. Where the replay lands depends on `--target` and on
whether a transport server has already been provided.

```bash
# hardware. The harness takes out one Fog job per transaction, wrapping the
# compute stage; `fog submit` exports the worker's URL for that child.
python3 harness/run_submission.py 0 --target FOG

# in-process simulator, to check a hardware result against.
python3 harness/run_submission.py 0 --target local
```

`--target local` runs the client's bundled `fhetch_sim` against the recorded
project on disk, which is the cheapest way to check that a change still produces
the right answer.

With `NBCC_FHETCH_SERVER` already set, the harness replays against that server and
takes out no jobs, which is what happens under a `fog submit` wrapper.

Failing both, it starts a local `nbcc_fhetch_replay_server` with `--exec` pointing
at a backend from a released Niobium SDK located via `--sdk`. That is a self-test
for someone who has the SDK, not the path this repository documents.

Success: the forwarder logs `POSTing … bytes (streamed, project=…, target=…)`
followed by the job's URL, then `unpacked N probe file(s)`, and the decrypted
scores agree with the plaintext reference to within CKKS approximation error.
Firmware time is not among the outputs: no stage here emits one.

## `--opt-level O3` is what the harness passes

The forwarder takes `--opt-level=<O0..O3>` and passes it to the backend, whose
own default is O0. This workload is recorded and replayed at O3, which the
harness passes on every Niobium target; lower levels are not exercised here.

Spell it as `--opt-level O3` or `--opt-level=O3` when running a stage by hand. A
bare `-O3` is not matched and is dropped, leaving the backend at O0.

Older niobium-fhetch pins do not forward the flag at all, in which case the
backend uses its default regardless of what you ask for.

## The payload is streamed, not buffered

Keys and the baked model weights are packed into every request, since the
transport is stateless, so a request body runs to about 5 GB. Neither side holds
one in memory: the forwarder streams the archive to the socket with chunked
transfer encoding, and the server feeds the incoming body straight into an
incremental unpacker. Peak host RSS over a single-transaction Fog run measures
around 4 GB against a 5.3 GB body.

Transactions are sequential requests, each in its own job, so the peak is one
transaction's payload however many are run. What grows with the size is the total
uploaded, not the memory needed to upload it.