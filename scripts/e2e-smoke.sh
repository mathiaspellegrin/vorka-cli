#!/usr/bin/env bash
set -euo pipefail

# Real end-to-end proof: starts a local Anvil devnet, deploys VorkaVault +
# VorkaVaultFactory onto it via the actual Foundry deploy script, then runs
# e2e-smoke.ts (the companion CLI's own keystore/signing/chain code) through
# a full create-vault -> fund -> withdraw -> rotate-auth flow against that
# real deployment, asserting on-chain state after each step. Proves the
# contracts and vorka-cli genuinely interoperate, not just isolated unit
# tests on either side.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPANION_DIR="$(dirname "$SCRIPT_DIR")"
ROOT_DIR="$(dirname "$COMPANION_DIR")"

# Anvil account #0 — well-known default test key, same every run.
export DEPLOYER_PRIVATE_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

ANVIL_LOG="$(mktemp)"
ANVIL_PID=""

cleanup() {
  if [[ -n "$ANVIL_PID" ]]; then
    kill "$ANVIL_PID" 2>/dev/null || true
  fi
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT

echo "==> Starting anvil..."
anvil --silent > "$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!

for _ in $(seq 1 20); do
  if cast chain-id --rpc-url http://127.0.0.1:8545 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done

echo "==> Deploying VorkaVault + VorkaVaultFactory..."
cd "$ROOT_DIR"
DEPLOY_OUTPUT="$(forge script script/DeployVorka.s.sol --rpc-url local --broadcast 2>&1)"
echo "$DEPLOY_OUTPUT"

FACTORY_ADDRESS="$(echo "$DEPLOY_OUTPUT" | grep "VorkaVaultFactory:" | tail -1 | awk '{print $NF}')"
if [[ -z "$FACTORY_ADDRESS" ]]; then
  echo "FAILED: could not find deployed VorkaVaultFactory address in forge script output"
  exit 1
fi
echo "==> Factory deployed at $FACTORY_ADDRESS"

echo "==> Running e2e smoke test against it..."
cd "$COMPANION_DIR"
npx tsx scripts/e2e-smoke.ts "$FACTORY_ADDRESS"
