// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Web Worker hosting the OpenFHE WASM module. Keygen and each rotation-key
// generation take seconds to minutes at ring 2^16 — off the main thread so the
// page stays live. The secret key exists only inside this worker's heap
// (exported only on explicit exportKeys, for IndexedDB persistence).

importScripts("fhe/fraud_fhe.js");

let mod = null;

async function ensureModule() {
  // locateFile: the loader resolves the .wasm relative to this worker's URL
  // by default, which points at the site root — pin it to fhe/.
  if (!mod) mod = await FraudFHEModule({ locateFile: (f) => `fhe/${f}` });
  return mod;
}

const handlers = {
  async init() {
    await ensureModule();
    return {};
  },
  async keygen() {
    const m = await ensureModule();
    m.keygen();
    return { rotKeys: m.rotationKeyCount() };
  },
  async importKeys({ cc, pk, sk }) {
    const m = await ensureModule();
    m.importKeys(new Uint8Array(cc), new Uint8Array(pk), new Uint8Array(sk));
    return {};
  },
  async exportKeys() {
    const m = await ensureModule();
    const cc = m.serializeCryptoContext().buffer;
    const pk = m.serializePublicKey().buffer;
    const sk = m.serializeSecretKey().buffer;
    return { result: { cc, pk, sk }, transfer: [cc, pk, sk] };
  },
  async serialize({ what }) {
    const m = await ensureModule();
    const fn = { cc: "serializeCryptoContext", mk: "serializeMultKey" }[what];
    if (!fn) throw new Error(`unknown serialize target ${what}`);
    const buf = m[fn]().buffer;
    return { result: buf, transfer: [buf] };
  },
  async rotKeyPart({ i }) {
    const m = await ensureModule();
    const buf = m.genRotationKeyPart(i).buffer;
    return { result: buf, transfer: [buf] };
  },
  async encrypt({ features }) {
    const m = await ensureModule();
    const buf = m.encryptRow(features).buffer;
    return { result: buf, transfer: [buf] };
  },
  async decrypt({ ct }) {
    const m = await ensureModule();
    return { result: m.decryptResult(new Uint8Array(ct)) };
  },
};

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    const out = (await handlers[op](args || {})) || {};
    const payload = "result" in out ? out.result : out;
    self.postMessage({ id, ok: true, result: payload }, out.transfer || []);
  } catch (err) {
    self.postMessage({ id, ok: false, error: String(err && err.message || err) });
  }
};
