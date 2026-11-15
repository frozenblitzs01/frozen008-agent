#!/usr/bin/env bash
# Download the official gatekeeper circuit artifacts from agentgames.zkverify.io.
# Run: npm run download-circuits   (or: bash scripts/download-circuits.sh)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/circuits"
mkdir -p "$DIR"

echo "Downloading gatekeeper circuit artifacts..."
curl -sL --retry 3 -o "$DIR/gatekeeper.wasm" \
  https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL --retry 3 -o "$DIR/gatekeeper_final.zkey" \
  https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey

# Verification key (needed to verify proofs locally; also used by lib/proof.js)
if command -v npx >/dev/null 2>&1; then
  (cd "$(dirname "$DIR")" && npx --yes snarkjs@0.7.5 zkey export verificationkey \
    circuits/gatekeeper_final.zkey circuits/verification_key.json >/dev/null 2>&1 || true)
fi

ls -la "$DIR"
sha256sum "$DIR/gatekeeper.wasm" "$DIR/gatekeeper_final.zkey"

# Expected SHA-256 (verified 2026-11-15):
#   gatekeeper.wasm        be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f
#   gatekeeper_final.zkey  adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d
