// Copyright (c) 2026 Niobium Microsystems, Inc.
// SPDX-License-Identifier: Apache-2.0

// Shared helpers for the file-staged client/server stages.
//
// The FHE client/server split:
// the CLIENT holds the secret key (keygen / encrypt / decrypt) and the SERVER
// computes on ciphertext only — it never sees the secret key. The stages hand
// data across the boundary as serialized files in a shared --io-dir, the same
// encrypt -> serialize -> compute -> serialize -> decrypt cost a real FHE
// deployment (and the FPGA) pays. Staging through files rather than a socket is
// what lets each stage be run and timed on its own.
//
// Deliberately free of any niobium/compiler.h include so the client stages
// (keygen / encrypt / decrypt) never pull in the recorder — only the server
// compute stage does.

#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "nb_telemetry/timing_summary.h"

namespace fraud {

// ── CKKS params (informational) ──────────────────────────────────────────────
// The real parameters are baked into the HEIR kernel
// (run_inference__generate_crypto_context): MultDepth 15, FIXEDMANUAL,
// ring 65536, HEStd_128_classic. These constants are for logging / telemetry
// `detail` strings only — the kernel is the source of truth.
constexpr uint32_t RING_DIM   = 65536;
constexpr uint32_t MULT_DEPTH = 15;

// The kernel's deep, heavily-rescaled CKKS result must have its scaling factor
// reset to 2^55 before decrypt (the HEIR codegen tracks it manually). Both the
// single-process driver and the old socket client applied this; the decrypt
// stage applies it after loading the result ciphertext.
inline double resultScalingFactor() { return std::pow(2.0, 55); }

// ── --help ───────────────────────────────────────────────────────────────────
// Every stage answers --help before it does any work. The shared parser ignores
// flags it does not know, so without this guard --help falls through to the
// ordinary path and the stage just runs: keygen would write a full keyset,
// secret key included, into the current directory.
inline bool helpRequested(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string s(argv[i]);
    if (s == "--help" || s == "-h") return true;
  }
  return false;
}

// `what` describes the stage; `extra` adds its own flags to the shared list.
inline void printUsage(const char* prog, const std::string& what,
                       const std::string& extra = "") {
  std::cout
    << "usage: " << prog << " [CSV] [--io-dir DIR] [--row N]\n\n"
    << what << "\n\n"
    << "  CSV               transactions to read (default data/test_rows.csv)\n"
       "  --io-dir DIR      directory the stages hand data through (default .)\n"
       "  --row N           which transaction to score (default 0)\n"
    << extra
    << "  --help            print this and exit without doing anything\n\n"
       "The four stages run in order: keygen, encrypt, server, decrypt, and are\n"
       "normally driven by harness/run_submission.py. It does not use the defaults\n"
       "above: it points --io-dir at io/<dataset>/<size> and picks the CSV from its\n"
       "own --data. Running a stage by hand means naming both, or it will read the\n"
       "wrong transactions and write into the current directory.\n";
}

// ── CLI common to every stage: [csv] --io-dir DIR --row N ────────────────────
// io-dir is the shared directory the stages hand data through (cc / keys /
// inputs / results). Unknown args are ignored so
// per-stage extras (e.g. the server's --target, consumed by the
// niobium compiler) don't trip the shared parser.
struct CommonArgs {
  std::string io_dir = ".";
  int         row    = 0;
  std::string csv    = "data/test_rows.csv";
};

inline CommonArgs parseCommonArgs(int argc, char** argv) {
  CommonArgs a;
  for (int i = 1; i < argc; ++i) {
    std::string s(argv[i]);
    if (s == "--io-dir" && i + 1 < argc)    a.io_dir = argv[++i];
    else if (s == "--row" && i + 1 < argc)  a.row = std::stoi(argv[++i]);
    else if (s.rfind("--row=", 0) == 0)     a.row = std::stoi(s.substr(6));
    else if (!s.empty() && s[0] != '-')     a.csv = s;
    // everything else (e.g. --target, --opt-level ...) is ignored here.
  }
  return a;
}

// ── File-name conventions shared across stages ───────────────────────────────
inline std::string ccFile(const std::string& d) { return d + "/cc.bin"; }
inline std::string pkFile(const std::string& d) { return d + "/pk.bin"; }
inline std::string skFile(const std::string& d) { return d + "/sk.bin"; }
inline std::string mkFile(const std::string& d) { return d + "/mk.bin"; }  // EvalMult key
inline std::string rkFile(const std::string& d) { return d + "/rk.bin"; }  // EvalAutomorphism keys
inline std::string inputFile(const std::string& d, int row) {
  return d + "/cipher_input_" + std::to_string(row) + ".bin";
}
// The compute stage tags THIS path, and it is what a replay re-reads. It has to
// be a fixed name: the input manifest records a source path at record time and
// is only rewritten by stop(), so a per-row name would pin the first row's file
// forever. The per-row inputFile() copies are kept purely as evidence.
inline std::string stagedInputFile(const std::string& d) {
  return d + "/cipher_input.bin";
}
inline std::string resultFile(const std::string& d, int row) {
  return d + "/cipher_result_" + std::to_string(row) + ".bin";
}
// The encrypt stage records the true label so the decrypt stage can print it
// beside its verdict without re-reading the (potentially huge) feature CSV.
inline std::string truthFile(const std::string& d, int row) {
  return d + "/truth_" + std::to_string(row) + ".txt";
}

// ── CSV reader (label + 82 standardized features) ────────────────────────────
struct TestRow {
  int                label = 0;  // 1 = fraud, 0 = ok
  std::vector<float> features;
};

inline std::vector<TestRow> read_csv(const std::string& path) {
  std::vector<TestRow> rows;
  std::ifstream file(path);
  if (!file.is_open()) {
    std::cerr << "ERROR: cannot open " << path << std::endl;
    return rows;
  }
  std::string line;
  std::getline(file, line);  // header
  while (std::getline(file, line)) {
    if (line.empty()) continue;
    std::stringstream ss(line);
    std::string val;
    TestRow row;
    std::getline(ss, val, ',');
    row.label = std::stoi(val);
    while (std::getline(ss, val, ',')) row.features.push_back(std::stof(val));
    rows.push_back(row);
  }
  return rows;
}

inline const char* truthStr(int label) { return label ? "FRAUD" : "OK"; }

}  // namespace fraud
