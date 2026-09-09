// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// fraud_client_decrypt — client-side result decryption (holds the secret key).
//
// Loads the crypto context + secret key and the server's encrypted logits,
// resets the scaling factor (HEIR tracks it manually), decrypts, takes argmax
// over the two class logits, and reports the prediction vs the recorded truth.
// Appends a row to <io>/results.csv, which the harness checks against the
// plaintext reference.
//
// Usage: fraud_client_decrypt --io-dir DIR --row N

#include <chrono>
#include <iomanip>
#include <fstream>
#include <iostream>

#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "fraud_model.inc.h"
#include "fraud_bench_common.h"

using namespace lbcrypto;

int main(int argc, char** argv) try {
  if (fraud::helpRequested(argc, argv)) {
    fraud::printUsage(argv[0],
      "Stage 4 of 4 (client): decrypts the logits with the secret key, prints the\n"
      "fraud verdict and appends a row to results.csv.");
    return 0;
  }
  auto args = fraud::parseCommonArgs(argc, argv);
  const std::string& io = args.io_dir;
  const int row = args.row;

  auto wall_start = std::chrono::high_resolution_clock::now();

  // ── Load context + secret key ──
  CryptoContextT cc;
  if (!Serial::DeserializeFromFile(fraud::ccFile(io), cc, SerType::BINARY) || !cc)
    throw std::runtime_error("Failed to load cc from " + fraud::ccFile(io));
  PrivateKeyT sk;
  if (!Serial::DeserializeFromFile(fraud::skFile(io), sk, SerType::BINARY) || !sk)
    throw std::runtime_error("Failed to load sk from " + fraud::skFile(io));

  // ── Load the server's encrypted result ──
  CiphertextT res;
  if (!Serial::DeserializeFromFile(fraud::resultFile(io, row), res, SerType::BINARY))
    throw std::runtime_error("Failed to load result from " + fraud::resultFile(io, row));
  res->SetScalingFactor(fraud::resultScalingFactor());

  // ── Decrypt + classify ──
  std::vector<CiphertextT> out = {res};
  auto logits = run_inference__decrypt__result0(cc, out, sk);
  if (logits.size() < 2)
    throw std::runtime_error("decrypt produced fewer than 2 logits");
  int pred = (logits[1] > logits[0]) ? 1 : 0;

  // ── Recorded truth (written by the encrypt stage) ──
  int truth = -1;
  { std::ifstream tf(fraud::truthFile(io, row)); if (tf) tf >> truth; }
  bool agree = (truth >= 0) && (pred == truth);

  std::cout << "Row " << std::setw(4) << row
            << "  truth=" << std::setw(5) << (truth < 0 ? "?" : fraud::truthStr(truth))
            << "  pred=" << std::setw(5) << fraud::truthStr(pred)
            << "  L[0]=" << std::fixed << std::setprecision(4) << logits[0]
            << "  L[1]=" << logits[1]
            << "  " << (truth < 0 ? "[no-truth]" : (agree ? "[agree]" : "[DISAGREE]"))
            << std::endl;

  // ── Append to results.csv (write header on first row) ──
  {
    std::string csv = io + "/results.csv";
    bool exists = std::filesystem::exists(csv);
    std::ofstream rf(csv, std::ios::app);
    if (!exists) rf << "row,truth,pred,logit0,logit1,agree" << std::endl;
    rf << row << "," << truth << "," << pred << ","
       << std::fixed << std::setprecision(6) << logits[0] << ","
       << logits[1] << "," << (agree ? 1 : 0) << std::endl;
  }

  nb::TimingSummary ts;
  ts.role = "decrypt"; ts.workload = "Fraud"; ts.mode = "CPU";
  ts.detail = "row" + std::to_string(row);
  ts.wall_ms = nb::elapsed_ms(wall_start);
  nb::write_timing_summary(ts);

  // Exit 0 on a successful decrypt regardless of agreement (the harness checks
  // results.csv against the plaintext reference); only I/O / decode failures
  // are non-zero.
  return 0;
} catch (const std::exception& e) {
  std::cerr << "[decrypt] error: " << e.what() << std::endl;
  return 1;
}
