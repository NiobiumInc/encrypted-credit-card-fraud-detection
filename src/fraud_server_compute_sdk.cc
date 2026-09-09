// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// fraud_server_compute_sdk — server-side encrypted compute over the transport.
//
// Linked against the niobium-client SDK's libnbfhetch, so replay() dispatches to
// `nbcc_fhetch_replay`
// (→ the FHETCH transport when NBCC_FHETCH_SERVER / NBCC_FHETCH_REPLAY are set).
//
// Uses the explicit niobium-fhetch API: capture_crypto_context / tag_input /
// tag_keys, with the hardware data format selected by --target.
//
// Records the trace once on a cache miss, in hollow mode (which computes
// nothing), and then ALWAYS replays. The backend is therefore the only source of
// a result. One invocation per row: the crypto context and its 1.8 GB of
// rotation keys are deserialized once, not once per pass.

#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "fraud_model.inc.h"
#include "fraud_bench_common.h"

#ifdef NIOBIUM_COMPILER
#include "niobium/compiler.h"   // resolved from niobium-fhetch/include (SDK version)
#endif

using namespace lbcrypto;

int main(int argc, char** argv) try {
  // Ahead of the #ifdef: compiler().init() below consumes argv, so the help
  // check has to run before it.
  if (fraud::helpRequested(argc, argv)) {
    fraud::printUsage(argv[0],
      "Stage 3 of 4 (server): evaluates the fraud model on the encrypted\n"
      "transaction and writes the encrypted logits to --io-dir. This is the\n"
      "stage that uses Niobium: it records the circuit once, then replays it\n"
      "on the backend named by --target.",
      "  --target NAME     replay backend: local (default) or FOG for an FPGA\n"
      "  --opt-level LVL   forwarded to the backend, which defaults to O0; the\n"
      "                    harness passes O3. Spell it this way: a bare -O3 is\n"
      "                    ignored, leaving the backend at its own default.\n");
    return 0;
  }
#ifdef NIOBIUM_COMPILER
  // Capture the flags that change the recorded trace before init() consumes
  // them: the target fixes the backend data format and the opt level fixes the
  // trace layout, so both belong in the cache key below.
  std::string nb_target, nb_opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a(argv[i]);
    if      (a.rfind("--target=", 0) == 0)          nb_target = a.substr(9);
    else if (a == "--target"     && i + 1 < argc)   nb_target = argv[i + 1];
    else if (a.rfind("--opt-level=", 0) == 0)       nb_opt    = a.substr(12);
    else if (a == "--opt-level"  && i + 1 < argc)   nb_opt    = argv[i + 1];
    else if (a.size() == 3 && a.rfind("-O", 0) == 0) nb_opt   = a.substr(1);
  }
  niobium::compiler().init(argc, argv);   // consumes --target=
  // Cooperative mode: this program keeps the record/replay decisions, but
  // replay reads the project from disk instead of relying on in-memory
  // captured inputs, which are incomplete on a cache-hit run. Must run
  // before the crypto context is loaded.
  niobium::compiler().enable_auto_tagging();
  niobium::compiler().set_program_info("fraud-inference", "1.0",
                                       "HEIR fraud MLP, deg5 ReLU, no-bootstrap (SDK)");
  niobium::compiler().set_build_info(__FILE__, __LINE__, __TIMESTAMP__);
#endif
  auto args = fraud::parseCommonArgs(argc, argv);
  const std::string& io = args.io_dir;
  const int row = args.row;

  auto wall_start = std::chrono::high_resolution_clock::now();

  // ── Load crypto context + eval keys (NO secret key) ──
  CryptoContextT cc;
  if (!Serial::DeserializeFromFile(fraud::ccFile(io), cc, SerType::BINARY) || !cc)
    throw std::runtime_error("Failed to load cc from " + fraud::ccFile(io));
  {
    std::ifstream mk(fraud::mkFile(io), std::ios::in | std::ios::binary);
    if (!mk.is_open() || !cc->DeserializeEvalMultKey(mk, SerType::BINARY))
      throw std::runtime_error("Failed to load EvalMult key from " + fraud::mkFile(io));
  }
  {
    std::ifstream rk(fraud::rkFile(io), std::ios::in | std::ios::binary);
    if (!rk.is_open() || !cc->DeserializeEvalAutomorphismKey(rk, SerType::BINARY))
      throw std::runtime_error("Failed to load rotation keys from " + fraud::rkFile(io));
  }

  std::cout << "[server-sdk] ring=" << cc->GetRingDimension()
            << " primes="
            << cc->GetCryptoParameters()->GetElementParams()->GetParams().size()
            << " row=" << row << std::endl;

  // ── Load the client's encrypted input row ──
  CiphertextT input_ct;
  if (!Serial::DeserializeFromFile(fraud::stagedInputFile(io), input_ct, SerType::BINARY))
    throw std::runtime_error("Failed to load input from " + fraud::stagedInputFile(io));
  std::vector<CiphertextT> enc = {input_ct};

  std::vector<CiphertextT> out;
  double compute_ms = 0.0;

#ifdef NIOBIUM_COMPILER
  niobium::Compiler::CacheParameters params;
  // The row is deliberately NOT part of the key. Every row runs the identical
  // circuit -- same weights, same instruction trace -- so one recording serves
  // all of them. The row's own ciphertext
  // reaches the replay through the staged input above, not through the trace.
  // Target and opt level DO belong here: both change the recorded trace, and
  // without them a run at one setting would replay the trace made at another.
  if (!nb_target.empty()) params.push_back({"target", nb_target});
  if (!nb_opt.empty())    params.push_back({"opt", nb_opt});
  niobium::compiler().cache_parameters(params);

  // Explicit tagging BEFORE start() (mult-server order): crypto context, the
  // input ciphertext, then the eval keys loaded in cc.
  niobium::compiler().capture_crypto_context(cc);
  // Tagged WITH its path: on a cache hit the trace is reused, and this is what
  // lets the replay pick up this row's ciphertext from disk instead of the one
  // the recording was made against.
  niobium::compiler().tag_input("cipher_input", enc[0], fraud::stagedInputFile(io));
  niobium::compiler().tag_keys(cc);

  const bool replaying = niobium::compiler().is_cache_valid();
  if (!replaying) {
    std::cout << "[server-sdk] recording trace for row " << row << " ..." << std::endl;
    niobium::compiler().start();

    // Baked weight plaintexts: encoded in-process. Build with recording paused
    // (the MAKE_PLAINTEXT macro in the kernel also pauses encode), then tag each.
    niobium::compiler().pause();
    auto prep = run_inference__preprocessing(cc);
    auto tag_vec = [](const std::vector<Plaintext>& v, const std::string& base) {
      for (size_t i = 0; i < v.size(); ++i)
        niobium::compiler().tag_input(base + "_" + std::to_string(i), v[i]);
    };
    tag_vec(prep.arg0,  "w0");  tag_vec(prep.arg1,  "w1");
    tag_vec(prep.arg2,  "w2");  tag_vec(prep.arg3,  "w3");
    tag_vec(prep.arg4,  "w4");  tag_vec(prep.arg5,  "w5");
    tag_vec(prep.arg6,  "w6");  tag_vec(prep.arg7,  "w7");
    tag_vec(prep.arg8,  "w8");  tag_vec(prep.arg9,  "w9");
    tag_vec(prep.arg10, "w10"); tag_vec(prep.arg11, "w11");
    tag_vec(prep.arg12, "w12"); tag_vec(prep.arg13, "w13");
    tag_vec(prep.arg14, "w14"); tag_vec(prep.arg15, "w15");
    niobium::compiler().resume();

    // Hollow recording: this pass exists to capture the instruction trace, not
    // to compute, so the FHE math is skipped. Must be on only for the math --
    // off for the tag_input() calls above, and off again before probe/stop,
    // which both serialize values the skipped math never produced.
    niobium::compiler().enable_hollow_mode(true);

    auto t_compute = std::chrono::high_resolution_clock::now();
    auto recorded = run_inference__preprocessed(cc, enc,
        prep.arg0,  prep.arg1,  prep.arg2,  prep.arg3,
        prep.arg4,  prep.arg5,  prep.arg6,  prep.arg7,
        prep.arg8,  prep.arg9,  prep.arg10, prep.arg11,
        prep.arg12, prep.arg13, prep.arg14, prep.arg15);
    compute_ms = nb::elapsed_ms(t_compute);
    niobium::compiler().enable_hollow_mode(false);
    recorded[0]->SetScalingFactor(fraud::resultScalingFactor());

    niobium::compiler().probe("result", recorded[0]);
    niobium::compiler().stop();

    std::cout << "[server-sdk] record done, trace only (record=" << compute_ms
              << " ms)" << std::endl;
  }

  // ── Always replay ── hollow recording computed nothing and a cache hit ran no
  // FHE at all, so the result can only come from the backend. Ships the trace
  // over the FHETCH transport when NBCC_FHETCH_SERVER / NBCC_FHETCH_REPLAY are
  // set; otherwise replays in-process through the bundled simulator.
  std::cout << "[server-sdk] replaying row " << row << " ..." << std::endl;
  auto t_replay = std::chrono::high_resolution_clock::now();
  if (!niobium::compiler().replay()) {
    std::cerr << "[ERROR] replay failed!" << std::endl;
    return 1;
  }
  CiphertextT res;
  if (!niobium::compiler().result(cc, "result", res)) {
    std::cerr << "[ERROR] Failed to get result!" << std::endl;
    return 1;
  }
  res->SetScalingFactor(fraud::resultScalingFactor());
  out = {res};
  compute_ms = nb::elapsed_ms(t_replay);
  std::cout << "[server-sdk] replay done (compute=" << compute_ms << " ms)" << std::endl;
#else
#error "fraud_server_compute_sdk.cc must be built with NIOBIUM_COMPILER"
#endif

  // ── Serialize the encrypted logits for the client to decrypt ──
  if (!Serial::SerializeToFile(fraud::resultFile(io, row), out[0], SerType::BINARY))
    throw std::runtime_error("Failed to serialize " + fraud::resultFile(io, row));
  std::cout << "[server-sdk] wrote " << fraud::resultFile(io, row) << std::endl;

  // ── Telemetry ──
  nb::TimingSummary ts;
  ts.role         = "server";
  ts.workload     = "Fraud";
  ts.mode         = "SDK";
  ts.detail       = "row" + std::to_string(row);
  ts.wall_ms      = nb::elapsed_ms(wall_start);
  ts.t_compute_ms = compute_ms;
  nb::write_timing_summary(ts);

  return 0;
} catch (const std::exception& e) {
  std::cerr << "[server-sdk] error: " << e.what() << std::endl;
  return 1;
}
