#!/usr/bin/env python3
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""
run_submission.py - one entry point for the encrypted credit card fraud detection workload.

    python3 harness/run_submission.py 0                # in-process simulator
    python3 harness/run_submission.py 2                # 20 transactions
    python3 harness/run_submission.py 0 --target FOG   # Niobium hardware over the transport
    python3 harness/run_submission.py 2 --rows 100     # override the row count

Pipeline (setup once, then per row):
    keygen  ->  [ encrypt -> compute -> decrypt ]*

Backends (chosen by --target):
    local        replay in-process through the client's bundled fhetch_sim. No
                 server, no backend, no credentials. The default.
    <nb target>  replay over the FHETCH transport on a Niobium backend (FOG).

The compute stage (fraud_server_sdk) links the niobium-client SDK (libnbfhetch).
On a cache miss it records the trace in hollow mode, which computes nothing, and
then it always replays. The answer therefore always comes from the backend.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from params import (InstanceParams, SINGLE, MEDIUM, instance_name, RING_DIM, MULT_DEPTH,
                    MODEL_SHAPE, DATASETS, DEFAULT_DATASET)
import cleartext_impl as cleartext

REPO = Path(__file__).resolve().parent.parent
CLIENT = REPO / "niobium-client"
FOG = CLIENT / "scripts" / "fog"     # jobs-as-a-service CLI

# Slack allowed between a decrypted logit and the plaintext reference. The
# logits are on a scale of roughly +/-5 and a genuinely wrong answer is off by
# whole units, so this only has to absorb CKKS approximation error. Measured on
# ring 2^16: 6.65e-07 on a single row, 1.13e-06 across 20 — and the same to every
# digit on the simulator and on an FPGA over the Fog. The default leaves four
# orders of magnitude of headroom and still catches drift a verdict check cannot.
REFERENCE_TOL = 0.05




def run(cmd, **kw):
    """Run a stage, raising on failure."""
    subprocess.run([str(c) for c in cmd], check=True, **kw)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def build_shim(sdk):
    """Give the flat released SDK the build/ layout fhetch_server.sh expects:
    $SHIM/build/ symlinks the SDK's bin/* + lib/*.so* so its --exec resolves
    nbcc_fhetch_replay to the SDK backend."""
    shim = Path(os.environ.get("SHIM", Path.home() / "nbcc-compiler-shim"))
    build = shim / "build"
    if not (build / "nbcc_fhetch_replay").exists():
        if shim.exists():
            shutil.rmtree(shim)
        build.mkdir(parents=True)
        for pat in ("bin/*", "lib/*.so*", "lib/*.dylib*"):
            for f in sdk.glob(pat):
                (build / f.name).symlink_to(f)
    return shim


def nbfhetch_dir():
    """Directory holding the just-built libnbfhetch (added to the lib path)."""
    for base in ("build/vendor/niobium-fhetch", "build/_deps/niobium-fhetch-build"):
        d = CLIENT / base
        if any(d.glob("libnbfhetch.*")):
            return d
    return None


def start_transport_server(sdk, shim, port, log_path):
    """Start the niobium-client fhetch server (execs the SDK replay backend via
    the shim). Returns the Popen; caller must terminate it."""
    env = dict(os.environ)
    env.update(
        PORT=str(port),
        BIND="127.0.0.1",
        PATH=f"{shim / 'build'}:{env.get('PATH', '')}",
        NIOBIUM_SPEC_DIR=str(sdk / "share/niobium/devices"),
        NIOBIUM_COMPILER_ROOT=str(shim),
    )
    log = open(log_path, "w")
    proc = subprocess.Popen(
        ["./scripts/fhetch_server.sh"], cwd=str(CLIENT), env=env, stdout=log, stderr=subprocess.STDOUT
    )
    # Wait for /healthz (or a server that died early).
    url = f"http://127.0.0.1:{port}/healthz"
    for _ in range(120):
        if proc.poll() is not None:
            raise RuntimeError(f"transport server exited early — see {log_path}")
        rc = subprocess.run(["curl", "-sf", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc.returncode == 0:
            print(f"[harness] transport server healthy on :{port}")
            return proc
        time.sleep(1)
    proc.terminate()
    raise RuntimeError(f"transport server never became healthy — see {log_path}")


def read_bounds(repo):
    """Per-feature standardized range from data/feature_bounds.csv, or None.

    The activation is a degree-5 Chebyshev fit over the training range. A
    feature far outside that range drives the pre-activations well beyond it,
    where the polynomial diverges instead of flattening: row 573 of stream_1k
    is 34% over on the amount and its logits reach ~4e+05, far outside the
    scale the result was encoded for. Such a row fails its reference check, or
    fails to decrypt at all.

    This note names the feature responsible, which the failure itself does
    not. It prints from the reference check, so a row that fails earlier — in
    decrypt, where logits this large cannot be decoded — never reaches it.
    """
    path = repo / "data" / "feature_bounds.csv"
    if not path.exists():
        return None
    lo, hi = [], []
    for i, line in enumerate(path.read_text().splitlines()):
        if i == 0 or not line.strip():
            continue
        cols = line.split(",")
        if len(cols) < 4:
            continue
        try:
            lo.append(float(cols[2])); hi.append(float(cols[3]))
        except ValueError:
            pass
    return (lo, hi) if lo else None


def check_bounds(features, bounds):
    """Indices of features outside the range, worst first."""
    if not bounds:
        return []
    lo, hi = bounds
    out = []
    for i, v in enumerate(features):
        if i >= len(lo):
            break
        span = hi[i] - lo[i]
        if v < lo[i]:
            out.append((i, v, (lo[i] - v) / span if span else 0.0))
        elif v > hi[i]:
            out.append((i, v, (v - hi[i]) / span if span else 0.0))
    out.sort(key=lambda t: -t[2])
    return out


def reference_check(results_csv, data_csv, tol=None):
    """Compare every decrypted row against the plaintext reference.

    A wrong FHE result can still land on the right verdict. This recomputes
    the same forward pass in the clear and compares the logits the run actually
    produced, so drift that keeps the verdict is still caught.
    """
    if not results_csv.exists():
        return []
    model = cleartext.load_model()
    bounds = read_bounds(REPO)
    checks = []
    for i, line in enumerate(results_csv.read_text().splitlines()):
        if i == 0 or not line.strip():
            continue
        cols = line.split(",")
        if len(cols) < 5:
            continue
        try:
            row, l0, l1 = int(cols[0]), float(cols[3]), float(cols[4])
        except ValueError:
            continue
        _, features = cleartext.read_features(data_csv, row)
        for i, v, frac in check_bounds(features, bounds)[:1]:
            print(f"[harness] note: row {row} feature {i} = {v:.4g} is "
                  f"{frac:.0%} outside its standardized range, where neither the "
                  f"fitted activation nor the level budget is expected to hold")
        ref, _ = cleartext.run(features, model)
        dev = max(abs(l0 - ref[0]), abs(l1 - ref[1]))
        agrees = (l1 > l0) == cleartext.is_fraud(ref)
        checks.append({
            "row": row,
            "deviation": dev,
            "verdict_agrees": agrees,
            "ok": agrees and (not tol or dev <= tol),
        })
    return checks


def main():
    # The stages write straight to this process's stdout. Without line buffering
    # our own prints are held back when the output is piped, and the transcript
    # comes out with the harness lines after the stage they introduce.
    sys.stdout.reconfigure(line_buffering=True)

    ap = argparse.ArgumentParser(description="Run the encrypted credit card fraud detection workload.")
    ap.add_argument("size", type=int, choices=range(SINGLE, MEDIUM + 1),
                    help="number of transactions: 0=1 / 1=5 / 2=20 (capped to --data). "
                         "Each transaction is its own backend round trip; use --rows N to go longer")
    ap.add_argument("--data", default=DEFAULT_DATASET, choices=list(DATASETS),
                    help="dataset: stream (default, 1000-txn ~10%% fraud anomaly stream) / "
                         "realistic (~0.5%% fraud, true rate) / balanced (20-row QA) / "
                         "fraud (all-fraud set)")
    ap.add_argument("--target", default="local",
                    help="local (default; in-process simulator, no backend or credentials) "
                         "or a Niobium backend id run over the transport (FOG is the stable "
                         "alias for Niobium hardware)")
    ap.add_argument("--rows", type=int, help="override the size's row count (rows 0..N-1)")
    ap.add_argument("--row", type=int, help="run a single specific row")
    ap.add_argument("--reference-tol", type=float, default=REFERENCE_TOL,
                    help=f"fail a row whose logits deviate from the plaintext reference by "
                         f"more than this (default {REFERENCE_TOL}). The verdict is always "
                         f"compared. Pass a larger value to loosen, or 0 to compare the "
                         f"verdict alone")
    ap.add_argument("-O", "--optimization", type=int, default=3, choices=[0, 1, 2, 3],
                    help="replay opt level (default 3; O3 compacts the trace to fit device memory)")
    ap.add_argument("--sdk", type=Path,
                    default=Path(os.environ.get("SDK", Path.home() / "niobium-sdk")),
                    help="released SDK dir providing the replay backend (or set SDK=)")
    ap.add_argument("--port", type=int, help="transport server port (default: a free port)")
    ap.add_argument("--build-dir", type=Path, default=REPO / "build")
    ap.add_argument("--io-dir", type=Path, help="stage io-dir (default io/<size>)")
    ap.add_argument("--keep", action="store_true", help="reuse keys + caches from a previous run")
    ap.add_argument("--skip-build", action="store_true")
    args = ap.parse_args()

    params = InstanceParams(args.size, args.data, REPO)
    # "local" replays in-process through the client's bundled fhetch_sim: no
    # transport server, no backend, no credentials. It is the out-of-the-box
    # way to exercise the Niobium path.
    is_local = args.target.lower() == "local"
    # Set by `fog submit`, which points it at the worker it leased. When present
    # the replay ships there, and this harness must not start a local server or
    # overwrite the variable with one.
    ext_server = os.environ.get("NBCC_FHETCH_SERVER")
    bdir = args.build_dir
    io = args.io_dir or params.iodir()
    csv = params.get_csv()
    optflag = f"O{args.optimization}"

    # Row list.
    if args.row is not None:
        row_list = [args.row]
    else:
        n = args.rows if args.rows is not None else params.get_num_rows()
        avail = sum(1 for _ in csv.open()) - 1  # minus header
        n = min(n, avail)
        row_list = list(range(n))

    print(f"\n[harness] fraud detection: {len(row_list)} transaction(s) from '{args.data}' "
          f"({DATASETS[args.data]['desc']})")
    print(f"[harness] model {MODEL_SHAPE}, ring 2^16, depth {MULT_DEPTH}  |  size={instance_name(args.size)}")
    backend = (f"Niobium in-process simulator (local), O{args.optimization}" if is_local else
               f"Niobium over transport ({args.target}), O{args.optimization}")
    print(f"[harness] backend: {backend}")
    # A Fog job carries one reservation and one replay consumes it, so a job has
    # to wrap a single compute stage rather than the whole run. With no server
    # already in the environment the harness provisions one job per transaction,
    # which also keeps keygen and encryption outside the job's window.
    fog_jobs = (not is_local) and (not ext_server) and FOG.exists()
    if ext_server and not is_local:
        print(f"[harness] using the caller's transport server: {ext_server}")
    elif fog_jobs:
        print("[harness] Fog jobs: one per transaction, wrapping the compute stage")

    # 1. Build if needed. The niobium-client submodule brings its own OpenFHE and
    #    libnbfhetch; scripts/build_task.sh builds both and the app against them.
    if not args.skip_build and not (bdir / "fraud_server_sdk").exists():
        run([REPO / "scripts" / "build_task.sh"])
    keygen = bdir / "fraud_client_keygen"
    encrypt = bdir / "fraud_client_encrypt"
    decrypt = bdir / "fraud_client_decrypt"
    server = bdir / "fraud_server_sdk"
    for b in (keygen, encrypt, decrypt, server):
        if not b.exists():
            sys.exit(f"error: missing {b} — run scripts/build_task.sh, or drop --skip-build")

    # 2. Runtime lib path: the client's own OpenFHE + libnbfhetch [+ a shim for the
    #    released-SDK backend when replaying over the transport].
    nbf = nbfhetch_dir()
    libs = [str(CLIENT / "vendor/lib/openfhe/lib")]
    if nbf:
        libs.append(str(nbf))
    shim = None
    sim = None
    if is_local:
        sim = next((c for c in (CLIENT / "build/vendor/niobium-fhetch/fhetch_sim",
                                CLIENT / "build/_deps/niobium-fhetch-build/fhetch_sim")
                    if c.exists()), None)
        if sim is None:
            sys.exit("error: --target local needs the fhetch_sim worker from the client "
                     "build — run scripts/build_task.sh first")
        os.environ["NBCC_FHETCH_SIM"] = str(sim)
    elif not ext_server and not fog_jobs:
        shim = build_shim(args.sdk)
        libs.append(str(shim / "build"))
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        os.environ[var] = ":".join(libs + [os.environ.get(var, "")])
    os.environ["NB_TIMING_SUMMARY_DIR"] = str(io)

    # 3. Fresh io-dir + recorded traces + keygen once. The trace is keyed on the
    #    target and opt level, not on the keys, so a trace left over from a
    #    previous run would still look valid and would replay against the keys it
    #    was recorded with, not the ones just generated. The glob has to match
    #    however the cache key names the directory.
    if not args.keep or not (io / "cc.bin").exists():
        if io.exists():
            shutil.rmtree(io)
        io.mkdir(parents=True)
        for c in REPO.glob("fraud-inference_*"):
            shutil.rmtree(c, ignore_errors=True)
        run([keygen, "--io-dir", io])
    (io / "results.csv").unlink(missing_ok=True)

    # 4. Transport server (Niobium targets only).
    srv = None
    fwd = CLIENT / "build/src/fhetch_transport/nbcc_fhetch_replay"
    port = args.port or free_port()
    srv_log = io / "transport_server.log"
    try:
        if not is_local and not ext_server and not fog_jobs:
            srv = start_transport_server(args.sdk, shim, port, srv_log)
        server_url = ext_server or (None if fog_jobs else f"http://127.0.0.1:{port}")

        # 5. Per-row: encrypt -> compute (record if cold, then replay) -> decrypt.
        t0 = time.time()
        for r in row_list:
            print(f"\n=== row {r} ===")
            run([encrypt, csv, "--io-dir", io, "--row", r])
            # Drop any result from an earlier run so decrypt cannot read a
            # leftover ciphertext if the compute stage below produces none.
            (io / f"cipher_result_{r}.bin").unlink(missing_ok=True)
            # One invocation: it records the trace if the cache is cold, then
            # always replays. The record pass is single-threaded; the replay runs
            # a fixed trace and is unaffected. Keep OMP_NUM_THREADS=1: recording
            # is not thread-safe here.
            # A local target replays in-process through fhetch_sim and needs no
            # transport env; anything else ships the trace to the server.
            env = dict(os.environ, OMP_NUM_THREADS="1")
            if not is_local and not fog_jobs:
                env.update(NBCC_FHETCH_SERVER=server_url, NBCC_FHETCH_REPLAY=str(fwd))
            compute = [server, "--io-dir", io, "--row", r, f"--target={args.target}",
                       "--opt-level", optflag]
            # `fog submit` leases the worker and exports the server, token and
            # replay binary for the child, so none of them are set here.
            run(([FOG, "submit"] + compute) if fog_jobs else compute, env=env)
            run([decrypt, "--io-dir", io, "--row", r])
        elapsed = time.time() - t0
    finally:
        if srv is not None:
            srv.terminate()
            try:
                srv.wait(timeout=10)
            except subprocess.TimeoutExpired:
                srv.kill()

    # 6. Summarize the run. The classifier is a fixture, so this reports what
    #    this run did, not how good the model is: see README "Checking the answer".
    total = sum(1 for i, line in enumerate((io / "results.csv").read_text().splitlines())
                if i and line.strip())
    # Name the backend in words, not as a bare token: whether this ran on real
    # hardware or the bundled simulator is the thing a reader most needs to know.
    print(f"\n=== summary ===")
    print(f"transactions: {total} from '{args.data}' ({DATASETS[args.data]['rows']}-txn set, "
          f"{DATASETS[args.data]['fraud_pct']:g}% fraud), scored in {elapsed:.1f}s")
    if is_local:
        print( "computed on:  the simulator bundled with the client, in-process — not hardware")
        print( "              pass --target FOG to run this on a Niobium FPGA")
    else:
        print(f"computed on:  a real Niobium FPGA, as a job on the Fog (--target {args.target})")

    # Primary correctness gate: the same forward pass, in the clear.
    ref = reference_check(io / "results.csv", csv, args.reference_tol)
    ref_bad = [c for c in ref if not c["ok"]]
    if ref:
        worst = max(c["deviation"] for c in ref)
        disagree = sum(1 for c in ref if not c["verdict_agrees"])
        print(f"reference:    {len(ref) - len(ref_bad)}/{len(ref)} rows match the plaintext "
              f"reference   (max logit deviation {worst:.2e}"
              + (f", tol {args.reference_tol:g}" if args.reference_tol is not None else "")
              + (f", {disagree} verdict mismatch" if disagree else "") + ")")


    fpga_us = None
    if not is_local and srv_log.exists():
        m = re.search(r"firmware FPGA time = (\d+) us", srv_log.read_text())
        if m:
            fpga_us = int(m.group(1))
            print(f"firmware FPGA time: {fpga_us/1000:.0f} ms/row (last replay)")

    params.measuredir().mkdir(parents=True, exist_ok=True)
    (params.measuredir() / "results.json").write_text(json.dumps({
        "dataset": args.data, "size": instance_name(args.size),
        "target": args.target, "opt_level": args.optimization,
        "rows": total,
        "reference_check": ref, "reference_tol": args.reference_tol,
        "wall_seconds": round(elapsed, 2),
        "ring_dim": RING_DIM, "mult_depth": MULT_DEPTH,
        # Only when the run produced it. The scrape reads a transport-server log,
        # which exists only when the harness starts that server itself; under
        # `fog submit` the server is remote, so no run on the documented paths
        # fills this. The parser is left in place for a stage that reports one.
        **({"firmware_fpga_us": fpga_us} if fpga_us is not None else {}),
    }, indent=2))

    if total == 0:
        sys.exit("error: no rows verified")
    if ref_bad:
        sys.exit(f"error: {len(ref_bad)} row(s) disagree with the plaintext reference "
                 f"(rows {', '.join(str(c['row']) for c in ref_bad[:10])})")
    print("\nDone. Every transaction above agreed with the plaintext reference.")


if __name__ == "__main__":
    main()
