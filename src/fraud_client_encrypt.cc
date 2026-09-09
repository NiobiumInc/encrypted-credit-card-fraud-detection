// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// fraud_client_encrypt — client-side input encryption (holds the secret key).
//
// Loads the crypto context + public key, reads one row of the feature CSV,
// encrypts it with the HEIR kernel's encrypt entrypoint, and serializes the
// ciphertext to the shared --io-dir (cipher_input_<row>.bin). Also records the
// true label (truth_<row>.txt) so the decrypt stage can print it beside its
// verdict without re-reading the CSV.
//
// Usage: fraud_client_encrypt [csv] --io-dir DIR --row N

#include <chrono>
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
      "Stage 2 of 4 (client): encrypts one transaction under the public key and\n"
      "writes it to --io-dir, both as cipher_input_<row>.bin and as the fixed\n"
      "cipher_input.bin the server stage reads.");
    return 0;
  }
  auto args = fraud::parseCommonArgs(argc, argv);
  const std::string& io = args.io_dir;
  const int row = args.row;

  auto wall_start = std::chrono::high_resolution_clock::now();

  // ── Load context + public key (no eval keys needed to encrypt) ──
  CryptoContextT cc;
  if (!Serial::DeserializeFromFile(fraud::ccFile(io), cc, SerType::BINARY) || !cc)
    throw std::runtime_error("Failed to load cc from " + fraud::ccFile(io));
  PublicKeyT pk;
  if (!Serial::DeserializeFromFile(fraud::pkFile(io), pk, SerType::BINARY) || !pk)
    throw std::runtime_error("Failed to load pk from " + fraud::pkFile(io));

  // ── Read the requested CSV row ──
  auto rows = fraud::read_csv(args.csv);
  if (rows.empty() || row < 0 || row >= static_cast<int>(rows.size()))
    throw std::runtime_error("Bad row " + std::to_string(row) + " (loaded " +
                             std::to_string(rows.size()) + " rows from " + args.csv + ")");
  const auto& r = rows[row];

  std::cout << "[encrypt] row " << row << " (truth=" << fraud::truthStr(r.label)
            << ", " << r.features.size() << " features)" << std::endl;

  // ── Encrypt + serialize ──
  auto enc = run_inference__encrypt__arg0(cc, r.features, pk);
  if (enc.empty())
    throw std::runtime_error("encrypt returned no ciphertext");
  if (!Serial::SerializeToFile(fraud::inputFile(io, row), enc[0], SerType::BINARY))
    throw std::runtime_error("Failed to serialize " + fraud::inputFile(io, row));

  // Stage the same ciphertext at the fixed path the compute stage tags. Written
  // last so its timestamp is the newest thing in the io-dir, which is what tells
  // a replay this row's input is not the one the trace was recorded against.
  if (!Serial::SerializeToFile(fraud::stagedInputFile(io), enc[0], SerType::BINARY))
    throw std::runtime_error("Failed to serialize " + fraud::stagedInputFile(io));

  // ── Record the true label for the decrypt stage ──
  {
    std::ofstream tf(fraud::truthFile(io, row));
    tf << r.label << std::endl;
  }

  std::cout << "[encrypt] wrote " << fraud::inputFile(io, row) << std::endl;

  nb::TimingSummary ts;
  ts.role = "encrypt"; ts.workload = "Fraud"; ts.mode = "CPU";
  ts.detail = "row" + std::to_string(row);
  ts.wall_ms = nb::elapsed_ms(wall_start);
  nb::write_timing_summary(ts);
  return 0;
} catch (const std::exception& e) {
  std::cerr << "[encrypt] error: " << e.what() << std::endl;
  return 1;
}
