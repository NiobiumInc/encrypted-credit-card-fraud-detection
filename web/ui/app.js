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
  // Loads the OpenFHE WASM module (web/wasm build output). Keygen streams each
  // evaluation key to the server as it is generated so peak memory stays low.
  constructor() { this.kind = "wasm"; }
  async setup(onProgress) {
    if (!window.FraudFHE) {
      throw new Error(
        "WASM module not present (web/ui/fhe/fraud_fhe.js). Build web/wasm, " +
        "or run the server with FRAUD_WEB_DEV=1 to use the dev scaffold.");
    }
    throw new Error("WasmClient wiring lands with the web/wasm build");
  }
  async encrypt() { throw new Error("not built"); }
  async decrypt() { throw new Error("not built"); }
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
    tr.innerHTML = `
      <td><input type="checkbox"></td>
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

  state.client = window.FraudFHE ? new WasmClient()
    : info.dev_mode ? new DevClient()
    : new WasmClient();
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
