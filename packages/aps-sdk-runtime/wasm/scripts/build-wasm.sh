#!/usr/bin/env bash
# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
# Build the APS runtime WASM verifier (batched check_many surface).
#
# Stage 1 (always runs): compile the crate to wasm32-unknown-unknown.
#   This produces the raw module at
#   target/wasm32-unknown-unknown/release/aps_sdk_runtime_wasm.wasm
#   and is the build path verified on this host.
#
# Stage 2 (environment-gated): generate JS/TS bindings with
#   wasm-bindgen-cli. Skipped automatically when wasm-bindgen is not on
#   PATH. The JS-loadable bundle is therefore pending a runner that has
#   wasm-bindgen-cli installed; it is NOT faked here.
#
# This script never installs anything into the shared repo root. The
# wasm32 target is a rustup component; wasm-bindgen-cli, if used, is a
# per-developer tool outside the repo.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

echo "[build-wasm] stage 1: cargo build --target wasm32-unknown-unknown"
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true
cargo build --release --target wasm32-unknown-unknown

wasm_out="target/wasm32-unknown-unknown/release/aps_sdk_runtime_wasm.wasm"
if [ -f "$wasm_out" ]; then
  echo "[build-wasm] wrote $here/$wasm_out"
else
  echo "[build-wasm] expected wasm artifact not found at $wasm_out" >&2
  exit 1
fi

if command -v wasm-bindgen >/dev/null 2>&1; then
  echo "[build-wasm] stage 2: wasm-bindgen JS bindings"
  mkdir -p pkg
  wasm-bindgen --target web --out-dir pkg "$wasm_out"
  echo "[build-wasm] wrote $here/pkg/"
else
  echo "[build-wasm] stage 2 SKIPPED: wasm-bindgen-cli not on PATH."
  echo "[build-wasm] The raw .wasm built; the JS-loadable bundle is environment-gated."
  echo "[build-wasm] Install with: cargo install wasm-bindgen-cli (matching wasm-bindgen crate version)."
fi
