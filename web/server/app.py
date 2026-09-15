# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
"""HTTP scoring service for the web demo — wraps stage 3 (fraud_server_sdk).

The four-stage split is unchanged; this service is the server side of the wire.
A browser session mirrors what the harness stages through --io-dir, but over
HTTP and with the keys cached per session instead of re-shipped per transaction:

    POST /api/sessions                      -> {session_id}
    PUT  /api/sessions/{sid}/keys/{name}    name in cc|mk|rk, raw body (~1.9 GB total, once)
    POST /api/sessions/{sid}/score          raw body = one transaction ciphertext (~17 MB);
                                            response = the encrypted logits (~1 MB)
    DELETE /api/sessions/{sid}

The service holds only what the FHE server may hold: the crypto context and the
evaluation keys. It refuses a secret key upload, and refuses to score while one
is present in the session directory — the same guard the trust boundary demands.

Each session gets its own working directory: the compute stage records its
trace on the first transaction (the trace binds to this session's keys and to
the staged-input path inside the session dir) and replays it for every later
one. Scoring within a session is sequential — the recorded trace re-reads a
fixed staged-input path, so requests hold the session lock.

Run:  uvicorn app:app --host 0.0.0.0 --port 8787
"""
import asyncio
import os
import re
import shutil
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build"
CLIENT = REPO / "niobium-client"
FOG = CLIENT / "scripts" / "fog"
SERVER_BIN = BUILD / "fraud_server_sdk"
SESSIONS = Path(os.environ.get("FRAUD_WEB_SESSIONS", REPO / "web" / "server" / "sessions"))
SESSION_TTL_S = int(os.environ.get("FRAUD_WEB_SESSION_TTL", 4 * 3600))
OPT_LEVEL = "O3"

KEY_NAMES = ("cc", "mk", "rk")
# Upper bounds only — a session upload beyond these is a client bug, not a
# bigger keyset (the kernel's parameters are fixed).
MAX_KEY_BYTES = {"cc": 64 << 20, "mk": 256 << 20, "rk": 4 << 30}
MAX_CT_BYTES = 64 << 20


def _fhetch_sim() -> Path | None:
    for c in (CLIENT / "build/vendor/niobium-fhetch/fhetch_sim",
              CLIENT / "build/_deps/niobium-fhetch-build/fhetch_sim"):
        if c.exists():
            return c
    return None


def _nbfhetch_dir() -> Path | None:
    for base in ("build/vendor/niobium-fhetch", "build/_deps/niobium-fhetch-build"):
        d = CLIENT / base
        if any(d.glob("libnbfhetch.*")):
            return d
    return None


def _stage_env() -> dict:
    env = dict(os.environ, OMP_NUM_THREADS="1")
    libs = [str(CLIENT / "vendor/lib/openfhe/lib")]
    nbf = _nbfhetch_dir()
    if nbf:
        libs.append(str(nbf))
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
        env[var] = ":".join(libs + [env.get(var, "")])
    sim = _fhetch_sim()
    if sim:
        env["NBCC_FHETCH_SIM"] = str(sim)
    return env


class Session:
    def __init__(self, sid: str):
        self.sid = sid
        self.dir = SESSIONS / sid
        self.dir.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()
        self.counter = 0
        self.touched = time.time()

    def key_path(self, name: str) -> Path:
        return self.dir / f"{name}.bin"

    def ready(self) -> bool:
        return all(self.key_path(n).exists() for n in KEY_NAMES)


app = FastAPI(title="encrypted-fraud-web")
sessions: dict[str, Session] = {}


def _session(sid: str) -> Session:
    s = sessions.get(sid)
    if s is None:
        raise HTTPException(404, "unknown session")
    s.touched = time.time()
    return s


def _gc_sessions() -> None:
    cutoff = time.time() - SESSION_TTL_S
    for sid in [sid for sid, s in sessions.items() if s.touched < cutoff]:
        s = sessions.pop(sid)
        shutil.rmtree(s.dir, ignore_errors=True)


@app.get("/api/info")
async def info():
    return {
        "targets": ["local"] + (["FOG"] if FOG.exists() else []),
        "keys": KEY_NAMES,
        "session_ttl_s": SESSION_TTL_S,
        "ring_dim": 65536,
        "mult_depth": 15,
        "dev_mode": DEV_MODE,
    }


@app.post("/api/sessions")
async def create_session():
    _gc_sessions()
    sid = uuid.uuid4().hex[:16]
    sessions[sid] = Session(sid)
    return {"session_id": sid}


async def _stream_to(request: Request, path: Path, limit: int, append: bool = False) -> int:
    if append:
        # Direct append (no tmp+rename): each archive lands whole in one
        # request, and a failed transfer truncates back to the pre-request size.
        base = path.stat().st_size if path.exists() else 0
        n = base
        try:
            with open(path, "ab") as f:
                async for chunk in request.stream():
                    n += len(chunk)
                    if n > limit:
                        raise HTTPException(413, f"file exceeds {limit} bytes")
                    f.write(chunk)
        except BaseException:
            with open(path, "ab") as f:
                f.truncate(base)
            raise
        return n
    n = 0
    tmp = path.with_suffix(".part")
    with open(tmp, "wb") as f:
        async for chunk in request.stream():
            n += len(chunk)
            if n > limit:
                f.close()
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, f"body exceeds {limit} bytes")
            f.write(chunk)
    tmp.rename(path)
    return n


@app.put("/api/sessions/{sid}/keys/{name}")
async def upload_key(sid: str, name: str, request: Request, append: bool = False):
    """Store one key file. `append=1` adds another archive to an existing file —
    the web client streams rotation keys one archive at a time (the compute
    stage accepts concatenated archives), keeping browser memory flat."""
    s = _session(sid)
    if name in ("sk", "pk"):
        # The secret key must never reach this host; the public key has no
        # business here either (the server only evaluates).
        raise HTTPException(403, f"refusing {name}: this host takes only cc/mk/rk")
    if name not in KEY_NAMES:
        raise HTTPException(400, f"unknown key '{name}' (want one of {KEY_NAMES})")
    async with s.lock:
        n = await _stream_to(request, s.key_path(name), MAX_KEY_BYTES[name], append=append)
    return {"received": n, "ready": s.ready()}


@app.get("/api/sessions/{sid}")
async def session_status(sid: str):
    s = _session(sid)
    return {
        "ready": s.ready(),
        "keys": {n: s.key_path(n).stat().st_size if s.key_path(n).exists() else None
                 for n in KEY_NAMES},
        "scored": s.counter,
    }


@app.post("/api/sessions/{sid}/score")
async def score(sid: str, request: Request, target: str = "local"):
    s = _session(sid)
    if not s.ready():
        raise HTTPException(409, "session keys incomplete (need cc, mk, rk)")
    if (s.dir / "sk.bin").exists():
        raise HTTPException(500, "a secret key is present in the session dir; refusing to run")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", target):
        raise HTTPException(400, "bad target")

    async with s.lock:
        row = s.counter
        s.counter += 1
        staged = s.dir / "cipher_input.bin"
        await _stream_to(request, staged, MAX_CT_BYTES)

        result = s.dir / f"cipher_result_{row}.bin"
        result.unlink(missing_ok=True)

        cmd = [str(SERVER_BIN), "--io-dir", str(s.dir), "--row", str(row),
               f"--target={target}", "--opt-level", OPT_LEVEL]
        if target.lower() != "local":
            if not FOG.exists():
                raise HTTPException(501, "Fog CLI not available on this host")
            cmd = [str(FOG), "submit"] + cmd
        t0 = time.time()
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=str(s.dir), env=_stage_env(),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        out, _ = await proc.communicate()
        total_ms = (time.time() - t0) * 1000
        log = out.decode(errors="replace")
        if proc.returncode != 0 or not result.exists():
            tail = "\n".join(log.splitlines()[-15:])
            raise HTTPException(502, f"compute stage failed (exit {proc.returncode}):\n{tail}")

        m = re.search(r"replay done \(compute=([\d.]+) ms\)", log)
        headers = {
            "X-Total-Ms": f"{total_ms:.0f}",
            "X-Compute-Ms": m.group(1) if m else "",
            "X-Target": target,
            "X-Row": str(row),
        }
        return Response(content=result.read_bytes(),
                        media_type="application/octet-stream", headers=headers)


# ── Dev mode ──────────────────────────────────────────────────────────────────
# FRAUD_WEB_DEV=1 exposes the native client stages over HTTP so the UI flow can
# be exercised before (or without) the browser WASM module. In dev mode the
# "client" is this same host: the secret key lives in web/server/devclient/,
# NOT in any session dir, so the score path's no-secret-key guard stays honest —
# but the browser is no longer the party holding the keys, and the UI says so.
DEV_MODE = os.environ.get("FRAUD_WEB_DEV") == "1"
DEV_DIR = Path(os.environ.get("FRAUD_WEB_DEVDIR", REPO / "web" / "server" / "devclient"))
DEV_CSV = REPO / "data" / "stream_1k.csv"
dev_lock = asyncio.Lock()


async def _run_stage(cmd: list[str], cwd: Path) -> str:
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=str(cwd), env=_stage_env(),
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await proc.communicate()
    log = out.decode(errors="replace")
    if proc.returncode != 0:
        tail = "\n".join(log.splitlines()[-10:])
        raise HTTPException(502, f"{Path(cmd[0]).name} failed (exit {proc.returncode}):\n{tail}")
    return log


def _dev_only():
    if not DEV_MODE:
        raise HTTPException(404, "dev mode is disabled (set FRAUD_WEB_DEV=1)")


@app.post("/api/dev/bootstrap")
async def dev_bootstrap():
    """Keygen natively (once) and provision a ready session from those keys."""
    _dev_only()
    async with dev_lock:
        if not (DEV_DIR / "cc.bin").exists():
            DEV_DIR.mkdir(parents=True, exist_ok=True)
            await _run_stage([str(BUILD / "fraud_client_keygen"), "--io-dir", str(DEV_DIR)],
                             DEV_DIR)
        sid = uuid.uuid4().hex[:16]
        s = Session(sid)
        for n in KEY_NAMES:
            shutil.copyfile(DEV_DIR / f"{n}.bin", s.key_path(n))
        sessions[sid] = s
    return {"session_id": sid, "dev": True}


@app.post("/api/dev/encrypt")
async def dev_encrypt(row: int):
    _dev_only()
    async with dev_lock:
        await _run_stage([str(BUILD / "fraud_client_encrypt"), str(DEV_CSV),
                          "--io-dir", str(DEV_DIR), "--row", str(row)], DEV_DIR)
        ct = (DEV_DIR / f"cipher_input_{row}.bin").read_bytes()
    return Response(content=ct, media_type="application/octet-stream")


@app.post("/api/dev/decrypt")
async def dev_decrypt(row: int, request: Request):
    _dev_only()
    async with dev_lock:
        await _stream_to(request, DEV_DIR / f"cipher_result_{row}.bin", MAX_CT_BYTES)
        log = await _run_stage([str(BUILD / "fraud_client_decrypt"),
                                "--io-dir", str(DEV_DIR), "--row", str(row)], DEV_DIR)
    m = re.search(r"L\[0\]=(-?[\d.]+)\s+L\[1\]=(-?[\d.]+)", log)
    if not m:
        raise HTTPException(502, "could not parse logits from decrypt output")
    l0, l1 = float(m.group(1)), float(m.group(2))
    return {"logits": [l0, l1], "fraud": l1 > l0, "score": l1 - l0}


@app.delete("/api/sessions/{sid}")
async def delete_session(sid: str):
    s = _session(sid)
    async with s.lock:
        sessions.pop(sid, None)
        shutil.rmtree(s.dir, ignore_errors=True)
    return {"deleted": sid}


# The UI (static files + transactions.json). Mounted last so /api wins.
UI_DIR = REPO / "web" / "ui"
if not (UI_DIR / "transactions.json").exists():
    # Generated, not committed: build it from the checked-in encoding metadata.
    import subprocess
    import sys
    subprocess.run([sys.executable, str(REPO / "web" / "data" / "make_display_dataset.py")],
                   check=True)
app.mount("/", StaticFiles(directory=UI_DIR, html=True), name="ui")
