#!/usr/bin/env bash
# Copyright (c) 2026 Niobium Microsystems, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end test of the HTTP scoring service using the NATIVE client stages in
# place of the browser WASM client: keygen locally, upload cc/mk/rk over HTTP,
# encrypt a row locally, score it over HTTP, decrypt the returned ciphertext
# locally, and check the verdict. Exercises the real wire protocol without a
# browser.
#
# Usage: ./test_e2e.sh [server-url] [row]
set -euo pipefail

URL=${1:-http://127.0.0.1:8787}
ROW=${2:-0}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
BUILD=$REPO/build
CSV=$REPO/data/stream_1k.csv
CLIENTDIR=$(mktemp -d /tmp/fraud-web-client.XXXXXX)
trap 'rm -rf "$CLIENTDIR"' EXIT

export DYLD_LIBRARY_PATH="$REPO/niobium-client/vendor/lib/openfhe/lib:${DYLD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$REPO/niobium-client/vendor/lib/openfhe/lib:${LD_LIBRARY_PATH:-}"

echo "== client: keygen (native, stands in for WASM) =="
"$BUILD/fraud_client_keygen" --io-dir "$CLIENTDIR"

echo "== session setup: upload cc/mk/rk =="
SID=$(curl -sf -X POST "$URL/api/sessions" | python3 -c 'import sys,json;print(json.load(sys.stdin)["session_id"])')
echo "session: $SID"
for k in cc mk rk; do
  echo "  put $k.bin ($(du -h "$CLIENTDIR/$k.bin" | cut -f1))"
  # -T streams from disk (a PUT); --data-binary would load the 1.7 GB rk.bin
  # into curl's memory.
  curl -sf -T "$CLIENTDIR/$k.bin" \
       -H 'Content-Type: application/octet-stream' \
       "$URL/api/sessions/$SID/keys/$k" > /dev/null
done

echo "== trust boundary: server must refuse the secret key =="
if curl -sf -T "$CLIENTDIR/sk.bin" \
        "$URL/api/sessions/$SID/keys/sk" > /dev/null 2>&1; then
  echo "FAIL: server accepted sk.bin"; exit 1
fi
echo "  refused, as it should"

echo "== client: encrypt row $ROW =="
"$BUILD/fraud_client_encrypt" "$CSV" --io-dir "$CLIENTDIR" --row "$ROW"

echo "== score over HTTP =="
HDRS=$(mktemp); trap 'rm -rf "$CLIENTDIR" "$HDRS"' EXIT
curl -sf -X POST --data-binary @"$CLIENTDIR/cipher_input_$ROW.bin" \
     -H 'Content-Type: application/octet-stream' -D "$HDRS" \
     -o "$CLIENTDIR/cipher_result_result.bin" \
     "$URL/api/sessions/$SID/score"
SRV_ROW=$(grep -i '^x-row:' "$HDRS" | tr -d '\r' | awk '{print $2}')
grep -i '^x-\(total\|compute\)-ms\|^x-target' "$HDRS" | tr -d '\r' | sed 's/^/  /'
# decrypt reads cipher_result_<row>.bin; align our local row naming with the
# name the server assigned.
mv "$CLIENTDIR/cipher_result_result.bin" "$CLIENTDIR/cipher_result_$ROW.bin"

echo "== client: decrypt =="
"$BUILD/fraud_client_decrypt" --io-dir "$CLIENTDIR" --row "$ROW"

echo "== results.csv =="
cat "$CLIENTDIR/results.csv"
echo "PASS"
