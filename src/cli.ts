#!/usr/bin/env node
import { Command } from "commander";
import { Contract, Wallet, ZeroAddress, parseEther, parseUnits } from "ethers";
import prompts from "prompts";
import path from "node:path";
import { backupKeystores, generateKeystores, unlockKeystores } from "./keystore.js";
import {
  CONFLUX_MAINNET_CHAIN_ID,
  CONFLUX_MAINNET_RPC,
  createVault,
  getProvider,
  getVaultState,
  submitExecute,
  submitModifyIdentity,
  submitWithdraw,
} from "./chain.js";
import { signExecute, signModifyIdentity, signWithdraw } from "./sign.js";
import { encodeActionCall, findAction, loadRegistry } from "./registry.js";
import { reviewActionCall } from "./review.js";

const program = new Command();
program.name("fluxpad").description("FluxPad companion CLI").version("0.1.0");

program
  .option("--dir <path>", "keystore directory (the mounted USB drive)", process.cwd())
  .option("--rpc <url>", "Conflux RPC endpoint", CONFLUX_MAINNET_RPC)
  .option("--chain-id <id>", "chain id for EIP-712 domain", String(CONFLUX_MAINNET_CHAIN_ID));

async function askPassword(message = "Password"): Promise<string> {
  const { password } = await prompts({ type: "password", name: "password", message });
  if (!password) throw new Error("Password required");
  return password;
}

async function requireBroadcaster(rpcUrl: string): Promise<Wallet> {
  const key = process.env.FLUXPAD_BROADCASTER_KEY;
  if (!key) {
    throw new Error(
      "Set FLUXPAD_BROADCASTER_KEY to a funded gas-paying account's private key. " +
        "This is separate from authAddress/fallbackAddress — it only pays Conflux gas, never holds vault assets.",
    );
  }
  return new Wallet(key, getProvider(rpcUrl));
}

async function parseTokenAmount(rpcUrl: string, token: string, amountStr: string): Promise<bigint> {
  if (token === ZeroAddress) return parseEther(amountStr);
  const erc20 = new Contract(token, ["function decimals() view returns (uint8)"], getProvider(rpcUrl));
  const decimals: number = await erc20.decimals();
  return parseUnits(amountStr, decimals);
}

program
  .command("generate")
  .description("Generate fresh auth/fallback keypairs and write encrypted keystores to --dir")
  .action(async () => {
    const opts = program.opts();
    const password = await askPassword("New password (protects both keys)");
    const confirm = await askPassword("Confirm password");
    if (password !== confirm) throw new Error("Passwords did not match");

    const { authAddress, fallbackAddress } = await generateKeystores(opts.dir, password);
    console.log(`authAddress:     ${authAddress}`);
    console.log(`fallbackAddress: ${fallbackAddress}`);
    console.log("Keep the fallback key's password safe and offline — it is the recovery root for this vault.");
  });

program
  .command("backup <destination>")
  .description("Copy both encrypted keystore files as-is to another location (no decryption)")
  .action(async (destination: string) => {
    const opts = program.opts();
    await backupKeystores(opts.dir, path.resolve(destination));
    console.log(`Copied encrypted keystores to ${destination}`);
  });

program
  .command("create-vault <factoryAddress>")
  .description("Deploy a new FluxVault clone with this drive's auth/fallback keys")
  .action(async (factoryAddress: string) => {
    const opts = program.opts();
    const password = await askPassword();
    const { auth, fallback } = await unlockKeystores(opts.dir, password);
    const broadcaster = await requireBroadcaster(opts.rpc);

    const vaultAddress = await createVault(factoryAddress, fallback.address, auth.address, broadcaster);
    console.log(`Vault deployed: ${vaultAddress}`);
  });

program
  .command("withdraw <vaultAddress> <token> <amount>")
  .description("Sign and broadcast a withdraw. token: address(0) for native ETH/CFX, or an ERC20 address")
  .action(async (vaultAddress: string, token: string, amount: string) => {
    const opts = program.opts();
    const provider = getProvider(opts.rpc);
    const state = await getVaultState(provider, vaultAddress);
    const amountWei = await parseTokenAmount(opts.rpc, token, amount);

    console.log(`This withdraws ${amount} (token ${token}) to owner: ${state.owner}`);
    const { confirmed } = await prompts({ type: "confirm", name: "confirmed", message: "Sign and broadcast?" });
    if (!confirmed) return;

    const password = await askPassword();
    const { auth } = await unlockKeystores(opts.dir, password);
    const signature = await signWithdraw(
      auth,
      { chainId: Number(opts.chainId), vaultAddress },
      token,
      amountWei,
      state.nonce,
    );

    const broadcaster = await requireBroadcaster(opts.rpc);
    const txHash = await submitWithdraw(vaultAddress, token, amountWei, signature, broadcaster);
    console.log(`Broadcast: ${txHash}`);
  });

program
  .command("list-actions")
  .description("List the curated actions execute() can be used against")
  .option("--registry <path>", "path to the actions registry", path.join(process.cwd(), "fluxpad-actions.json"))
  .action(async (cmdOpts) => {
    const actions = await loadRegistry(cmdOpts.registry);
    for (const action of actions) {
      console.log(`${action.id}: ${action.description} (${action.target})`);
    }
  });

program
  .command("execute <vaultAddress> <actionId> <argsJson>")
  .description('Build, review, sign, and broadcast a curated execute() call. argsJson: e.g. \'["0xSpender", "1000"]\'')
  .option("--registry <path>", "path to the actions registry", path.join(process.cwd(), "fluxpad-actions.json"))
  .option("--value <ether>", "native value to send with the call", "0")
  .action(async (vaultAddress: string, actionId: string, argsJson: string, cmdOpts) => {
    const opts = program.opts();
    const actions = await loadRegistry(cmdOpts.registry);
    const action = findAction(actions, actionId);
    if (!action) throw new Error(`Unknown action "${actionId}". Run list-actions to see what's available.`);

    const args = JSON.parse(argsJson) as unknown[];
    const data = encodeActionCall(action, args);
    const { summary, warnings } = reviewActionCall(action, data);

    console.log(summary);
    for (const warning of warnings) console.warn(`WARNING: ${warning}`);

    const { confirmed } = await prompts({ type: "confirm", name: "confirmed", message: "Sign and broadcast this call?" });
    if (!confirmed) return;

    const provider = getProvider(opts.rpc);
    const state = await getVaultState(provider, vaultAddress);
    const value = parseEther(cmdOpts.value);

    const password = await askPassword();
    const { auth } = await unlockKeystores(opts.dir, password);
    const signature = await signExecute(
      auth,
      { chainId: Number(opts.chainId), vaultAddress },
      action.target,
      value,
      data,
      state.nonce,
    );

    const broadcaster = await requireBroadcaster(opts.rpc);
    const txHash = await submitExecute(vaultAddress, action.target, value, data, signature, broadcaster);
    console.log(`Broadcast: ${txHash}`);
  });

async function rotate(
  vaultAddress: string,
  field: "auth" | "fallback",
  newAddress: string,
  dir: string,
  rpcUrl: string,
  chainId: number,
) {
  const provider = getProvider(rpcUrl);
  const state = await getVaultState(provider, vaultAddress);

  const password = await askPassword("Fallback key password");
  const { fallback } = await unlockKeystores(dir, password);

  const newOwner = ZeroAddress;
  const newFallback = field === "fallback" ? newAddress : ZeroAddress;
  const newAuth = field === "auth" ? newAddress : ZeroAddress;

  const signature = await signModifyIdentity(
    fallback,
    { chainId, vaultAddress },
    newOwner,
    newFallback,
    newAuth,
    state.nonce,
  );

  const broadcaster = await requireBroadcaster(rpcUrl);
  const txHash = await submitModifyIdentity(vaultAddress, newOwner, newFallback, newAuth, signature, broadcaster);
  console.log(`Broadcast: ${txHash}`);
}

program
  .command("rotate-auth <vaultAddress> <newAuthAddress>")
  .description("Replace the operational (USB) key — signed by the fallback key")
  .action(async (vaultAddress: string, newAuthAddress: string) => {
    const opts = program.opts();
    await rotate(vaultAddress, "auth", newAuthAddress, opts.dir, opts.rpc, Number(opts.chainId));
  });

program
  .command("rotate-fallback <vaultAddress> <newFallbackAddress>")
  .description("Replace the recovery root key — signed by the current fallback key")
  .action(async (vaultAddress: string, newFallbackAddress: string) => {
    const opts = program.opts();
    await rotate(vaultAddress, "fallback", newFallbackAddress, opts.dir, opts.rpc, Number(opts.chainId));
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
