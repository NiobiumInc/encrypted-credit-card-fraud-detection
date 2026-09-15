#!/usr/bin/env bash
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Build the browser FHE client: OpenFHE v1.5.1 compiled to WebAssembly, then
# the fraud_wasm module against it. Output: web/ui/fhe/fraud_fhe.{js,wasm}.
#
# Requirements: emsdk (source emsdk_env.sh first, or set EMSDK), cmake, git.
# NATIVE_SIZE=64 is mandatory: serialized objects must be wire-compatible with
# the native stages, which use 64-bit limbs.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
BUILD="$HERE/build"
SRC="$BUILD/openfhe-src"
INSTALL="$BUILD/openfhe-install"
OUT="$REPO/web/ui/fhe"

OPENFHE_TAG=${OPENFHE_TAG:-v1.5.1}
# Any clone of openfhe-development; used as a local object reference if set.
OPENFHE_GIT=${OPENFHE_GIT:-https://github.com/openfheorg/openfhe-development}
JOBS=${JOBS:-$(getconf _NPROCESSORS_ONLN)}

if ! command -v emcmake >/dev/null; then
  for cand in "$HOME/emsdk/emsdk_env.sh" "${EMSDK:-}/emsdk_env.sh"; do
    [ -f "$cand" ] && . "$cand" > /dev/null 2>&1 && break
  done
fi
command -v emcmake >/dev/null || { echo "error: emsdk not found (install ~/emsdk or set EMSDK)"; exit 1; }

mkdir -p "$BUILD" "$OUT"

# ── 1. OpenFHE source at the pinned tag ──────────────────────────────────────
if [ ! -d "$SRC/.git" ]; then
  echo "== cloning OpenFHE $OPENFHE_TAG =="
  git clone --depth 1 --branch "$OPENFHE_TAG" "$OPENFHE_GIT" "$SRC"
fi

# ── 2. OpenFHE -> wasm (static libs) ─────────────────────────────────────────
if [ ! -f "$INSTALL/lib/libOPENFHEpke_static.a" ]; then
  echo "== configuring OpenFHE for wasm =="
  mkdir -p "$SRC/build"
  (cd "$SRC/build" && emcmake cmake .. \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX="$INSTALL" \
      -DBUILD_SHARED=OFF -DBUILD_STATIC=ON \
      -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF \
      -DWITH_OPENMP=OFF -DNATIVE_SIZE=64 \
      -DCMAKE_CXX_FLAGS="-O2 -fexceptions" \
      -DCMAKE_C_FLAGS="-O2 -fexceptions")
  echo "== building OpenFHE (wasm) =="
  cmake --build "$SRC/build" -j "$JOBS"
  cmake --install "$SRC/build"
fi

# ── 3. fraud_wasm module ─────────────────────────────────────────────────────
echo "== building fraud_fhe module =="
INC=(-I"$INSTALL/include/openfhe"
     -I"$INSTALL/include/openfhe/core"
     -I"$INSTALL/include/openfhe/pke"
     -I"$INSTALL/include/openfhe/binfhe"
     -I"$INSTALL/include/openfhe/cereal"
     -I"$REPO/src"
     -I"$REPO/include")
LIBS=("$INSTALL/lib/libOPENFHEpke_static.a"
      "$INSTALL/lib/libOPENFHEbinfhe_static.a"
      "$INSTALL/lib/libOPENFHEcore_static.a")

em++ -O2 -std=c++17 -fexceptions \
  "${INC[@]}" \
  "$HERE/fraud_wasm.cc" "$REPO/src/fraud_model_lib.inc.cc" \
  "${LIBS[@]}" \
  --bind \
  -sDISABLE_EXCEPTION_CATCHING=0 \
  -sALLOW_MEMORY_GROWTH=1 \
  -sMAXIMUM_MEMORY=4294967296 \
  -sINITIAL_MEMORY=268435456 \
  -sSTACK_SIZE=8388608 \
  -sMODULARIZE=1 -sEXPORT_NAME=FraudFHEModule \
  -sENVIRONMENT=web,worker \
  -o "$OUT/fraud_fhe.js"

ls -lh "$OUT"
echo "OK: web/ui/fhe/fraud_fhe.{js,wasm}"
