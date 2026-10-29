#!/usr/bin/env bash
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
# build_task.sh — self-contained Niobium build: the niobium-client submodule
# builds its OWN OpenFHE + libnbfhetch, and the fraud stages build against that.
# Run from the repo root. See docs/NIOBIUM_CLIENT_TRANSPORT.md.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== [1/3] sync niobium-client (its OpenFHE + niobium-fhetch + cpp-httplib) ==="
git submodule update --init niobium-client
# niobium-client's only submodule is niobium-fhetch (OpenFHE nested in it);
# cpp-httplib is vendored in its tree.
make -C niobium-client sync

echo "=== [2/3] build the client's bundled OpenFHE + libnbfhetch + transport (make release) ==="
make -C niobium-client release        # installs OpenFHE to niobium-client/vendor/lib/openfhe

OPENFHE_PREFIX="$ROOT/niobium-client/vendor/lib/openfhe"
[[ -d "$OPENFHE_PREFIX" ]] || { echo "error: client OpenFHE not at $OPENFHE_PREFIX after 'make release'" >&2; exit 1; }

echo "=== [3/3] build fraud stages + SDK server against the client's OpenFHE ==="
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DNIOBIUM_SDK_BUILD=ON \
  -DCMAKE_PREFIX_PATH="$OPENFHE_PREFIX"
cmake --build build -j \
  --target fraud_client_keygen fraud_client_encrypt fraud_client_decrypt fraud_server_sdk

echo "=== done: binaries in $ROOT/build ==="
ls -la build/fraud_client_keygen build/fraud_client_encrypt \
       build/fraud_client_decrypt build/fraud_server_sdk
