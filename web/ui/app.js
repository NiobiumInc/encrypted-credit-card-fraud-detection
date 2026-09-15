// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Encrypted fraud detection — web client.
//
// The crypto client is pluggable behind one interface:
//   setup(onProgress)          -> session id (keys generated + eval keys uploaded)
//   encrypt(txn)               -> ArrayBuffer (one transaction ciphertext)
//   decrypt(buf, txn)          -> {logits: [l0, l1], fraud, score}
//
// WasmClient does all three in the browser (OpenFHE compiled to WebAssembly;
// the secret key never leaves the page). DevClient drives the native stages on
// the server over /api/dev/* — a scaffold for developing the UI and protocol,
// clearly badged, with no browser-side crypto.

const MAX_SELECT = 5;

const $ = (id) => document.getElementById(id);
const state = {
  info: null,
  client: null,
  sessionId: null,
  txns: [],
  selected: new Set(),
  running: false,
};

// ── crypto clients ────────────────────────────────────────────────────────────

class DevClient {
  constructor() { this.kind = "dev"; }
  async setup(onProgress) {
    onProgress("keygen + key upload on the server (dev mode)…", 0.3);
    const r = await fetch("/api/dev/bootstrap", { method: "POST" });
    if (!r.ok) throw new Error(await r.text());
    onProgress("session provisioned", 1);
    return (await r.json()).session_id;
  }
  async encrypt(txn) {
    const r = await fetch(`/api/dev/encrypt?row=${txn.id}`, { method: "POST" });
    if (!r.ok) throw new Error(await r.text());
    return await r.arrayBuffer();
  }
  async decrypt(buf, txn) {
    const r = await fetch(`/api/dev/decrypt?row=${txn.id}`, { method: "POST", body: buf });
    if (!r.ok) throw new Error(await r.text());
    return await r.json();
  }
}

class WasmClient {
  // OpenFHE compiled to WebAssembly, hosted in a Web Worker. Keygen runs in the
  // browser; the secret key never leaves the worker. Each rotation key is
  // generated, uploaded (append), and dropped one at a time so browser memory
  // stays flat while ~1.8 GB of evaluation keys stream to the server.
  constructor() {
    this.kind = "wasm";
    this.worker = null;
    this.pending = new Map();
    this.msgId = 0;
  }

  _call(op, args, transfer) {
    if (!this.worker) {
      this.worker = new Worker("fhe-worker.js");
      this.worker.onmessage = (e) => {
        const { id, ok, result, error } = e.data;
        const p = this.pending.get(id);
        if (!p) return;
        this.pending.delete(id);
        ok ? p.resolve(result) : p.reject(new Error(error));
      };
    }
    const id = ++this.msgId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, op, args }, transfer || []);
    });
  }

  async setup(onProgress) {
    onProgress("loading FHE module (WebAssembly)…", 0.01);
    await this._call("init");

    onProgress("generating keys in your browser (CKKS, ring 2¹⁶)…", 0.03);
    const { rotKeys } = await this._call("keygen");

    const r = await fetch("/api/sessions", { method: "POST" });
    if (!r.ok) throw new Error(await r.text());
    const sid = (await r.json()).session_id;

    const put = async (name, body, append) => {
      const resp = await fetch(
        `/api/sessions/${sid}/keys/${name}${append ? "?append=1" : ""}`,
        { method: "PUT", body });
      if (!resp.ok) throw new Error(await resp.text());
    };

    onProgress("uploading crypto context…", 0.06);
    await put("cc", await this._call("serialize", { what: "cc" }));
    onProgress("uploading relinearization key…", 0.08);
    await put("mk", await this._call("serialize", { what: "mk" }));

    for (let i = 0; i < rotKeys; i++) {
      onProgress(`rotation key ${i + 1}/${rotKeys} — generate in browser, upload, drop…`,
                 0.1 + 0.9 * (i / rotKeys));
      const part = await this._call("rotKeyPart", { i });
      await put("rk", part, i > 0);
    }
    onProgress("session ready — the secret key stays in this page", 1);
    return sid;
  }

  async encrypt(txn) {
    return await this._call("encrypt", { features: txn.features });
  }

  async decrypt(buf, _txn) {
    return await this._call("decrypt", { ct: buf }, [buf]);
  }
}

// ── scoring pipeline ──────────────────────────────────────────────────────────

async function scoreSelected() {
  if (state.running) return;
  state.running = true;
  $("btn-score").disabled = true;
  $("btn-score").classList.add("busy");
  const ids = [...state.selected];
  const target = $("target").value;

  for (const id of ids) {
    const txn = state.txns[id];
    const tr = document.querySelector(`tr[data-id="${id}"]`);
    setVerdict(tr, "scoring");
    try {
      const t0 = performance.now();
      status(`encrypting txn ${id}…`);
      const ct = await state.client.encrypt(txn);

      status(`scoring txn ${id} on '${target}' (encrypted end to end)…`);
      const resp = await fetch(
        `/api/sessions/${state.sessionId}/score?target=${encodeURIComponent(target)}`,
        { method: "POST", body: ct });
      if (!resp.ok) throw new Error(await resp.text());
      const computeMs = resp.headers.get("X-Compute-Ms");
      const result = await resp.arrayBuffer();

      status(`decrypting result for txn ${id}…`);
      const out = await state.client.decrypt(result, txn);
      const wallMs = performance.now() - t0;

      txn.result = { ...out, computeMs: Number(computeMs || 0), wallMs };
      setVerdict(tr, out.fraud ? "fraud" : "ok", out);
      state.selected.delete(id);
      tr.classList.remove("sel");
      tr.querySelector("input").checked = false;
      status(`txn ${id}: ${out.fraud ? "FRAUD" : "OK"} · gap ${out.score.toFixed(2)} · ` +
             `compute ${(txn.result.computeMs / 1000).toFixed(1)}s · total ${(wallMs / 1000).toFixed(1)}s`);
    } catch (e) {
      setVerdict(tr, "error");
      status(`txn ${id} failed: ${e.message}`);
      break;
    }
    updateSelCount();
  }

  state.running = false;
  $("btn-score").classList.remove("busy");
  updateSelCount();
}

// ── table ─────────────────────────────────────────────────────────────────────

function fmtMoney(v) {
  return v.toLocaleString("en-US", { style: "currency", currency: "USD" });
}

function setVerdict(tr, kind, out) {
  const cell = tr.querySelector("td.verdict");
  tr.classList.remove("scoring", "fraud", "ok");
  if (kind === "scoring") {
    tr.classList.add("scoring");
    cell.innerHTML = `<span class="chip wait">scoring…</span>`;
  } else if (kind === "fraud" || kind === "ok") {
    tr.classList.add(kind);
    const gap = out.score.toFixed(2);
    cell.innerHTML = `<span class="chip ${kind}">${kind === "fraud" ? "FRAUD" : "OK"}</span>
                      <span class="dim mono" title="logit gap (fraud − legit)"> ${gap > 0 ? "+" : ""}${gap}</span>`;
  } else if (kind === "error") {
    cell.innerHTML = `<span class="chip wait">error</span>`;
  } else {
    cell.innerHTML = "";
  }
}

function toggleRow(id) {
  if (state.txns[id].oob) return;  // outside the model's fitted range
  const tr = document.querySelector(`tr[data-id="${id}"]`);
  const box = tr.querySelector("input");
  if (state.selected.has(id)) {
    state.selected.delete(id);
  } else {
    if (state.selected.size >= MAX_SELECT) return;
    state.selected.add(id);
  }
  box.checked = state.selected.has(id);
  tr.classList.toggle("sel", state.selected.has(id));
  updateSelCount();
}

function updateSelCount() {
  $("sel-count").textContent = `${state.selected.size} of ${MAX_SELECT} selected`;
  $("btn-score").disabled = state.running || state.selected.size === 0;
}

function renderTable() {
  const tbody = document.querySelector("#txns tbody");
  const reveal = $("reveal").checked;
  const frag = document.createDocumentFragment();
  for (const t of state.txns) {
    const tr = document.createElement("tr");
    tr.dataset.id = t.id;
    if (t.oob) {
      tr.classList.add("oob");
      tr.title = "Outside the model's fitted feature range — the client filters " +
                 "this pre-flight (the activation polynomial diverges on it)";
    }
    tr.innerHTML = `
      <td><input type="checkbox" ${t.oob ? "disabled" : ""}></td>
      <td class="amount r">${fmtMoney(t.amount)}</td>
      <td>${t.merchant}</td>
      <td class="dim">${t.category}</td>
      <td>${t.holder}<span class="dim"> · ${t.gender} ${t.age}</span></td>
      <td class="dim">${t.city}, ${t.state}</td>
      <td class="dim">${t.day_of_week.slice(0, 3)} ${String(t.hour).padStart(2, "0")}:00 · ${t.month}</td>
      <td class="truth">${truthCell(t, reveal)}</td>
      <td class="verdict"></td>`;
    tr.addEventListener("click", (e) => {
      if (e.target.tagName !== "INPUT") e.preventDefault();
      toggleRow(t.id);
    });
    frag.appendChild(tr);
  }
  tbody.replaceChildren(frag);
}

function truthCell(t, reveal) {
  if (!reveal) return `<span class="truth-hidden">···</span>`;
  return t.truth
    ? `<span class="chip fraud">FRAUD</span>`
    : `<span class="chip ok">OK</span>`;
}

function refreshTruth() {
  const reveal = $("reveal").checked;
  for (const t of state.txns) {
    const cell = document.querySelector(`tr[data-id="${t.id}"] td.truth`);
    if (cell) cell.innerHTML = truthCell(t, reveal);
  }
}

function status(msg) { $("run-status").textContent = msg; }

// ── boot ──────────────────────────────────────────────────────────────────────

async function boot() {
  const [info, txns] = await Promise.all([
    fetch("/api/info").then((r) => r.json()),
    fetch("/transactions.json").then((r) => r.json()),
  ]);
  state.info = info;
  state.txns = txns.rows;

  const sel = $("target");
  for (const t of info.targets) {
    const o = document.createElement("option");
    o.value = o.textContent = t;
    sel.appendChild(o);
  }

  // Prefer real browser crypto whenever the WASM module has been built; the
  // dev scaffold is the fallback for UI work before/without it.
  const wasmAvailable =
    (await fetch("fhe/fraud_fhe.js", { method: "HEAD" })).ok;
  state.client = wasmAvailable ? new WasmClient()
    : info.dev_mode ? new DevClient()
    : new WasmClient();  // will fail with a pointer to web/wasm/build.sh
  $("dev-badge").hidden = state.client.kind !== "dev";
  $("max-sel").textContent = MAX_SELECT;

  $("btn-setup").addEventListener("click", startSession);
  $("btn-score").addEventListener("click", scoreSelected);
  $("reveal").addEventListener("change", refreshTruth);
}

async function startSession() {
  const btn = $("btn-setup");
  btn.disabled = true;
  btn.classList.add("busy");
  $("setup-progress").hidden = false;
  $("setup-error").hidden = true;
  try {
    state.sessionId = await state.client.setup((label, frac) => {
      $("setup-label").textContent = label;
      $("setup-bar").style.width = `${Math.round(frac * 100)}%`;
    });
    $("session-chip").textContent = `session ${state.sessionId.slice(0, 8)}`;
    $("session-chip").classList.add("live");
    $("setup").hidden = true;
    $("main").hidden = false;
    $("actionbar").hidden = false;
    renderTable();
    updateSelCount();
  } catch (e) {
    $("setup-error").textContent = e.message;
    $("setup-error").hidden = false;
    btn.disabled = false;
  } finally {
    btn.classList.remove("busy");
  }
}

boot();
