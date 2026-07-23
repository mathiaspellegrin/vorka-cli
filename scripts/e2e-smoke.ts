import { Wallet, ZeroAddress, parseEther } from "ethers";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { CHAINS, createVault, getProvider, getVaultState, submitModifyIdentity, submitWithdraw } from "../src/chain.js";
import { generateKeystores, unlockKeystores } from "../src/keystore.js";
import { signModifyIdentity, signWithdraw } from "../src/sign.js";

// Real end-to-end proof against a live Anvil devnet: generate keys, deploy a
// vault through the factory, fund it, withdraw, then rotate the operational
// key and confirm the rotation actually took. Exercises the same keystore/
// signing/chain code the real CLI commands use — just called directly,
// since `prompts`' password prompts don't work over piped/non-tty stdin
// (verified: it hangs waiting for real keypress events). Asserts on-chain
// state after each step; any mismatch throws and the whole script exits
// non-zero. Invoked by ../scripts/e2e-smoke.sh, which handles the anvil
// lifecycle and contract deployment.

// Anvil's default deterministic accounts (same every run, well-known test-only keys).
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // account #0
const NEW_AUTH_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"; // account #2

/**
 * Both `pending` and `latest` under-report the nonce immediately after an
 * auto-mined tx against this local Anvil (confirmed by direct testing —
 * ethers'/the provider's block-tag-relative queries lag behind what Anvil
 * actually just mined within the same tick), so back-to-back sends from one
 * signer in a single process collide. Only matters here because this script
 * sends several transactions from the same wallet in one run; the real CLI
 * never hits this (one broadcast per process, fresh nonce fetch each time).
 * Tracking the nonce locally — one real fetch, then increment ourselves —
 * sidesteps the RPC/provider staleness entirely, without touching chain.ts's
 * production nonce handling.
 */
class LocalNonceWallet extends Wallet {
  private nextNonce: number | null = null;

  override async getNonce(): Promise<number> {
    if (this.nextNonce === null) {
      this.nextNonce = await super.getNonce("latest");
    }
    return this.nextNonce++;
  }
}

function assertEqual(actual: unknown, expected: unknown, label: string) {
  if (actual !== expected) {
    throw new Error(`FAILED: ${label} — expected ${expected}, got ${actual}`);
  }
  console.log(`OK: ${label}`);
}

async function main() {
  const factoryAddress = process.argv[2];
  if (!factoryAddress) throw new Error("Usage: tsx e2e-smoke.ts <factoryAddress>");

  const chain = CHAINS.local;
  const provider = getProvider(chain.rpc);
  const broadcaster = new LocalNonceWallet(DEPLOYER_KEY, provider);
  const newAuth = new Wallet(NEW_AUTH_KEY, provider);

  const dir = await mkdtemp(path.join(tmpdir(), "vorka-e2e-"));
  const password = "smoke-test-password-not-real";
  const { authAddress, fallbackAddress } = await generateKeystores(dir, password);
  console.log(`Generated keys: auth=${authAddress} fallback=${fallbackAddress}`);

  console.log("\n--- create-vault ---");
  const vaultAddress = await createVault(factoryAddress, fallbackAddress, authAddress, broadcaster);
  console.log(`Vault deployed: ${vaultAddress}`);
  const initialState = await getVaultState(provider, vaultAddress);
  assertEqual(initialState.owner, broadcaster.address, "owner is the createVault caller");
  assertEqual(initialState.authAddress, authAddress, "authAddress matches generated key");
  assertEqual(initialState.fallbackAddress, fallbackAddress, "fallbackAddress matches generated key");
  assertEqual(initialState.nonce, 0n, "nonce starts at 0");

  console.log("\n--- fund vault ---");
  const fundTx = await broadcaster.sendTransaction({ to: vaultAddress, value: parseEther("1") });
  await fundTx.wait();
  const fundedBalance = await provider.getBalance(vaultAddress);
  assertEqual(fundedBalance, parseEther("1"), "vault balance after funding");

  console.log("\n--- withdraw ---");
  const { auth } = await unlockKeystores(dir, password);
  const withdrawAmount = parseEther("0.4");
  const withdrawSig = await signWithdraw(
    auth,
    { chainId: chain.chainId, vaultAddress },
    ZeroAddress,
    withdrawAmount,
    initialState.nonce,
  );
  await submitWithdraw(vaultAddress, ZeroAddress, withdrawAmount, withdrawSig, broadcaster);
  const balanceAfterWithdraw = await provider.getBalance(vaultAddress);
  assertEqual(balanceAfterWithdraw, parseEther("0.6"), "vault balance after withdrawing 0.4 ETH");
  const stateAfterWithdraw = await getVaultState(provider, vaultAddress);
  assertEqual(stateAfterWithdraw.nonce, 1n, "nonce consumed by withdraw");

  console.log("\n--- rotate-auth (fast-forwarding past the 24h governance cooldown) ---");
  await provider.send("evm_increaseTime", [90000]);
  await provider.send("evm_mine", []);
  const { fallback } = await unlockKeystores(dir, password);
  const rotateSig = await signModifyIdentity(
    fallback,
    { chainId: chain.chainId, vaultAddress },
    ZeroAddress,
    ZeroAddress,
    newAuth.address,
    stateAfterWithdraw.nonce,
  );
  await submitModifyIdentity(vaultAddress, ZeroAddress, ZeroAddress, newAuth.address, rotateSig, broadcaster);
  const stateAfterRotate = await getVaultState(provider, vaultAddress);
  assertEqual(stateAfterRotate.authAddress, newAuth.address, "authAddress rotated to the new key");
  assertEqual(stateAfterRotate.owner, initialState.owner, "owner unchanged by an auth-only rotation");
  assertEqual(stateAfterRotate.fallbackAddress, initialState.fallbackAddress, "fallbackAddress unchanged");

  console.log("\nALL CHECKS PASSED");
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
