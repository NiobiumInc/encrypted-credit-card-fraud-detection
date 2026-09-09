// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// fraud_client_keygen — client-side key generation (holds the secret key).
//
// Generates the CKKS crypto context, the key pair, and the evaluation keys
// (relin + rotation) baked in by the HEIR kernel, then serializes everything to
// the shared --io-dir:
//   cc.bin  pk.bin  sk.bin  mk.bin (EvalMult)  rk.bin (EvalAutomorphism)
//
// The server later loads cc + mk + rk only (never sk).

#include <chrono>
#include <fstream>
#include <iostream>

#include "openfhe.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "fraud_model.inc.h"
#include "fraud_bench_common.h"

using namespace lbcrypto;

int main(int argc, char** argv) try {
  if (fraud::helpRequested(argc, argv)) {
    fraud::printUsage(argv[0],
      "Stage 1 of 4 (client): generates the CKKS crypto context, the key pair and\n"
      "the evaluation keys, writing cc/pk/sk/mk/rk into --io-dir. sk.bin is the\n"
      "secret key and stays on the client.");
    return 0;
  }
  auto args = fraud::parseCommonArgs(argc, argv);
  const std::string& io = args.io_dir;
  std::filesystem::create_directories(io);

  auto wall_start = std::chrono::high_resolution_clock::now();

  std::cout << "[keygen] generating crypto context..." << std::endl;
  CryptoContextT cc = run_inference__generate_crypto_context();

  std::cout << "[keygen] generating key pair + eval keys..." << std::endl;
  auto keyPair = cc->KeyGen();
  cc = run_inference__configure_crypto_context(cc, keyPair.secretKey);

  std::cout << "[keygen] ring=" << cc->GetRingDimension()
            << " primes="
            << cc->GetCryptoParameters()->GetElementParams()->GetParams().size()
            << std::endl;

  // Context + public/secret keys.
  if (!Serial::SerializeToFile(fraud::ccFile(io), cc, SerType::BINARY))
    throw std::runtime_error("Failed to serialize cc to " + fraud::ccFile(io));
  if (!Serial::SerializeToFile(fraud::pkFile(io), keyPair.publicKey, SerType::BINARY))
    throw std::runtime_error("Failed to serialize pk to " + fraud::pkFile(io));
  if (!Serial::SerializeToFile(fraud::skFile(io), keyPair.secretKey, SerType::BINARY))
    throw std::runtime_error("Failed to serialize sk to " + fraud::skFile(io));

  // Evaluation keys (relin = EvalMult, rotation = EvalAutomorphism). Serialized
  // via the context member form — the server deserializes them into its context.
  {
    std::ofstream f(fraud::mkFile(io), std::ios::out | std::ios::binary);
    if (!f.is_open() || !cc->SerializeEvalMultKey(f, SerType::BINARY))
      throw std::runtime_error("Failed to serialize EvalMult key to " + fraud::mkFile(io));
  }
  {
    std::ofstream f(fraud::rkFile(io), std::ios::out | std::ios::binary);
    if (!f.is_open() || !cc->SerializeEvalAutomorphismKey(f, SerType::BINARY))
      throw std::runtime_error("Failed to serialize rotation keys to " + fraud::rkFile(io));
  }

  std::cout << "[keygen] wrote cc/pk/sk/mk/rk -> " << io << std::endl;

  nb::TimingSummary ts;
  ts.role = "keygen"; ts.workload = "Fraud"; ts.mode = "CPU"; ts.detail = "";
  ts.wall_ms = nb::elapsed_ms(wall_start);
  nb::write_timing_summary(ts);
  return 0;
} catch (const std::exception& e) {
  std::cerr << "[keygen] error: " << e.what() << std::endl;
  return 1;
}
