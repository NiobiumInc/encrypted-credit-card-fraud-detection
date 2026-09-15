# Web demo — encrypted fraud detection with a browser client

An interactive UI on top of the [four-stage demo](../README.md): the browser is
the FHE client (keygen, encrypt, decrypt — OpenFHE compiled to WebAssembly),
and an HTTP service wraps stage 3, the encrypted model evaluation. Pick
transactions from a scrolling table, score them, and watch them come back red
(fraud) or green (legitimate) — the server only ever sees ciphertext.

## Run it

```bash
# native side (once): builds OpenFHE, libnbfhetch, and the four stages
git submodule update --init niobium-client && ./scripts/build_task.sh

# browser crypto module (once, ~20 min): OpenFHE v1.5.1 -> WebAssembly
./web/wasm/build.sh          # needs emsdk (https://emscripten.org)

# the scoring service + UI
pip install -r web/server/requirements.txt
cd web/server && uvicorn app:app --port 8787
# open http://localhost:8787
```

Without the WASM module, run the server with `FRAUD_WEB_DEV=1` to drive the UI
through the native client stages instead (`/api/dev/*`); the page shows a DEV
MODE badge — the browser holds no keys in that mode.

## What the browser does

1. **Start session** — the page generates the CKKS key pair in a Web Worker
   (the secret key never leaves it), then uploads the evaluation material:
   crypto context + relinearization key, then each of the 26 rotation keys,
   generated → uploaded → dropped one at a time so browser memory stays flat
   (the full set is ~1.8 GB, beyond the wasm32 heap).
2. **Select up to 5 transactions** from the sample stream (~10% fraud — the
   deliberate demo compression; real traffic is ~0.5%).
3. Per transaction: encrypt in the worker (~17 MB ciphertext), POST to
   `/api/sessions/{sid}/score`, decrypt the returned encrypted logits (~1 MB),
   and paint the row red or green with the logit gap.

## Wire protocol

| Transfer | Size | When |
|---|---|---|
| cc + mk + rk (eval keys) | ~1.9 GB | once per session |
| transaction ciphertext ↑ | 16.8 MB | per transaction |
| encrypted logits ↓ | 1.1 MB | per transaction |

The service refuses `sk`/`pk` uploads and refuses to score while a secret key
is present in a session directory. Each session gets its own working dir; the
compute stage records its trace on the first transaction (~0.7 s) and replays
it for the rest (~15 s each on the local simulator on an M-series Mac; the
`FOG` target ships each job to a Niobium FPGA, at ~5 GB upload per job since
the transport is stateless).

Rotation keys upload as concatenated archives (`PUT …/keys/rk?append=1`); the
compute stage loops deserialization to EOF and OpenFHE merges per index, so the
single-archive native `rk.bin` and the 26-archive browser upload both work.

## Layout

```
web/
├── ui/            # static frontend (vanilla JS) + fhe-worker.js
│   └── fhe/       # WASM build output (fraud_fhe.js/.wasm), gitignored
├── wasm/          # browser FHE client: fraud_wasm.cc + build.sh
├── server/        # FastAPI scoring service (app.py), e2e wire test
└── data/          # display-dataset generation (inverse standardization)
```

`web/data/encoding_meta.json` (checked in) carries the StandardScaler
means/scales and ordinal decode tables that turn the z-scored feature CSVs back
into human-readable transactions; `make_display_dataset.py` pairs both into
`web/ui/transactions.json` (generated at server start if missing). The truth
label rides along for the post-scoring reveal toggle and is never sent to the
server.
