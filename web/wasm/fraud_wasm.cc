// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// fraud_wasm — the browser-side FHE client: keygen, encrypt, decrypt, compiled
// to WebAssembly against the same OpenFHE version (and NATIVE_SIZE=64) the
// native stages use, so every serialized object is wire-compatible with them.
//
// The secret key is created in the page and never leaves it. Rotation keys are
// generated and serialized ONE INDEX AT A TIME (~70 MB each) and handed to JS
// for upload, then dropped — full eval-key material is ~1.8 GB, far over the
// wasm32 heap, so it must never exist in memory at once.

#include <cmath>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include <emscripten/bind.h>
#include <emscripten/val.h>

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "fraud_model.inc.h"

using namespace lbcrypto;
namespace em = emscripten;

namespace {

CryptoContextT g_cc;
KeyPair<DCRTPoly> g_kp;

// The rotation indices the HEIR kernel's configure step generates — must match
// src/fraud_model_lib.inc.cc (run_inference__configure_crypto_context).
const std::vector<int32_t> kRotIndices = {64, 7,  40, 2, 9,  16, 4,  11, 120, 56, 108, 6,  96,
                                          32, 84, 1,  8, 72, 60, 3,  48, 10,  36, 24,  5,  12};

em::val toUint8Array(const std::string& s) {
  em::val view{em::typed_memory_view(s.size(), reinterpret_cast<const uint8_t*>(s.data()))};
  em::val out = em::val::global("Uint8Array").new_(s.size());
  out.call<void>("set", view);
  return out;
}

template <typename T>
std::string serializeToString(const T& obj) {
  std::stringstream ss;
  Serial::Serialize(obj, ss, SerType::BINARY);
  return ss.str();
}

template <typename T>
T deserializeFromJS(const em::val& bytes) {
  std::string s(bytes["length"].as<size_t>(), '\0');
  em::val view{em::typed_memory_view(s.size(), reinterpret_cast<uint8_t*>(&s[0]))};
  view.call<void>("set", bytes);
  std::stringstream ss(std::move(s));
  T obj;
  Serial::Deserialize(obj, ss, SerType::BINARY);
  return obj;
}

void requireKeys() {
  if (!g_cc || !g_kp.secretKey) throw std::runtime_error("call keygen() or importKeys() first");
}

}  // namespace

// ── keygen ────────────────────────────────────────────────────────────────────

// Creates the context and the key pair + relin key. Rotation keys are NOT
// generated here — pull them one at a time with genRotationKeyPart().
void keygen() {
  g_cc = run_inference__generate_crypto_context();
  g_kp = g_cc->KeyGen();
  g_cc->EvalMultKeyGen(g_kp.secretKey);
}

int rotationKeyCount() { return static_cast<int>(kRotIndices.size()); }

// One serialized automorphism-key archive for the i-th rotation index. The
// server appends archives; deserialization on the native side merges them.
em::val genRotationKeyPart(int i) {
  requireKeys();
  if (i < 0 || i >= static_cast<int>(kRotIndices.size()))
    throw std::runtime_error("rotation index out of range");
  const std::string tag = g_kp.secretKey->GetKeyTag();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(tag);
  g_cc->EvalRotateKeyGen(g_kp.secretKey, {kRotIndices[i]});
  std::stringstream ss;
  if (!CryptoContextImpl<DCRTPoly>::SerializeEvalAutomorphismKey(ss, SerType::BINARY, tag))
    throw std::runtime_error("failed to serialize rotation key");
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(tag);
  return toUint8Array(ss.str());
}

em::val serializeCryptoContext() { requireKeys(); return toUint8Array(serializeToString(g_cc)); }
em::val serializePublicKey()     { requireKeys(); return toUint8Array(serializeToString(g_kp.publicKey)); }
em::val serializeSecretKey()     { requireKeys(); return toUint8Array(serializeToString(g_kp.secretKey)); }

em::val serializeMultKey() {
  requireKeys();
  std::stringstream ss;
  if (!g_cc->SerializeEvalMultKey(ss, SerType::BINARY))
    throw std::runtime_error("failed to serialize mult key");
  return toUint8Array(ss.str());
}

// Import a previously exported cc/pk/sk bundle (IndexedDB restore, or the
// native-keygen fallback). Rotation/mult keys live server-side per session.
void importKeys(const em::val& ccBytes, const em::val& pkBytes, const em::val& skBytes) {
  g_cc = deserializeFromJS<CryptoContextT>(ccBytes);
  g_kp.publicKey = deserializeFromJS<PublicKeyT>(pkBytes);
  g_kp.secretKey = deserializeFromJS<PrivateKeyT>(skBytes);
}

// ── encrypt / decrypt ─────────────────────────────────────────────────────────

em::val encryptRow(const em::val& jsFeatures) {
  requireKeys();
  std::vector<float> features = em::convertJSArrayToNumberVector<float>(jsFeatures);
  auto enc = run_inference__encrypt__arg0(g_cc, features, g_kp.publicKey);
  if (enc.empty()) throw std::runtime_error("encrypt produced no ciphertext");
  return toUint8Array(serializeToString(enc[0]));
}

em::val decryptResult(const em::val& ctBytes) {
  requireKeys();
  auto ct = deserializeFromJS<CiphertextT>(ctBytes);
  // HEIR tracks the CKKS scale manually; the result decodes at 2^55 (same
  // reset the native decrypt stage applies).
  ct->SetScalingFactor(std::pow(2.0, 55));
  std::vector<CiphertextT> v = {ct};
  auto logits = run_inference__decrypt__result0(g_cc, v, g_kp.secretKey);
  if (logits.size() < 2) throw std::runtime_error("decrypt produced fewer than 2 logits");
  em::val out = em::val::object();
  out.set("logits", em::val::array(std::vector<double>{logits[0], logits[1]}));
  out.set("fraud", logits[1] > logits[0]);
  out.set("score", logits[1] - logits[0]);
  return out;
}

EMSCRIPTEN_BINDINGS(fraud_fhe) {
  em::function("keygen", &keygen);
  em::function("rotationKeyCount", &rotationKeyCount);
  em::function("genRotationKeyPart", &genRotationKeyPart);
  em::function("serializeCryptoContext", &serializeCryptoContext);
  em::function("serializePublicKey", &serializePublicKey);
  em::function("serializeSecretKey", &serializeSecretKey);
  em::function("serializeMultKey", &serializeMultKey);
  em::function("importKeys", &importKeys);
  em::function("encryptRow", &encryptRow);
  em::function("decryptResult", &decryptResult);
}
