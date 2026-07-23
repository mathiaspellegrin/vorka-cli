#!/usr/bin/env node
import { Command } from "commander";
import { Contract, Wallet, ZeroAddress, parseEther, parseUnits, type JsonRpcProvider } from "ethers";
import prompts from "prompts";
import path from "node:path";
import {
  backupKeystores,
  generateKeystores,
  readAddressManifest,
  unlockAuthKeystore,
  unlockFallbackKeystore,
} from "./keystore.js";
import {
  CHAINS,
  createVault,
  getValidatedProvider,
  getVaultState,
  signingDeadline,
  submitExecute,
  submitModifyIdentity,
  submitWithdraw,
  type ChainConfig,
} from "./chain.js";
import { signExecute, signModifyIdentity, signWithdraw } from "./sign.js";
import { encodeActionCall, findAction, loadRegistry } from "./registry.js";
import { reviewActionCall } from "./review.js";

const program = new Command();
program.name("vorka").description("Vorka companion CLI").version("0.1.0");

program
  .option("--dir <path>", "keystore directory (the mounted USB drive)", process.cwd())
  .option("--chain <name>", `chain to target (one of: ${Object.keys(CHAINS).join(", ")})`, "conflux-mainnet");

function activeChain(): ChainConfig {
  const name = program.opts().chain as string;
  const chain = CHAINS[name];
  if (!chain) {
    throw new Error(`Unknown chain "${name}". Supported: ${Object.keys(CHAINS).join(", ")}`);
  }
  return chain;
}

async function askPassword(message = "Password"): Promise<string> {
  const { password } = await prompts({ type: "password", name: "password", message });
  if (!password) throw new Error("Password required");
  return password;
}

async function requireBroadcaster(provider: JsonRpcProvider): Promise<Wallet> {
  const key = process.env.VORKA_BROADCASTER_KEY;
  if (!key) {
    throw new Error(
      "Set VORKA_BROADCASTER_KEY to a funded gas-paying account's private key. " +
        "This is separate from authAddress/fallbackAddress — it only pays gas on the active chain, never holds vault assets.",
    );
  }
  return new Wallet(key, provider);
}

async function parseTokenAmount(provider: JsonRpcProvider, token: string, amountStr: string): Promise<bigint> {
  if (token === ZeroAddress) return parseEther(amountStr);
  const erc20 = new Contract(token, ["function decimals() view returns (uint8)"], provider);
  const decimals: number = await erc20.decimals();
  return parseUnits(amountStr, decimals);
}

program
  .command("generate")
  .description("Generate fresh auth/fallback keypairs and write encrypted keystores to --dir")
  .action(async () => {
    const opts = program.opts();
    const authPassword = await askPassword("New auth (operational) password");
    const authConfirm = await askPassword("Confirm auth password");
    if (authPassword !== authConfirm) throw new Error("Auth passwords did not match");

    const fallbackPassword = await askPassword("New fallback (recovery) password — must differ from the auth password");
    const fallbackConfirm = await askPassword("Confirm fallback password");
    if (fallbackPassword !== fallbackConfirm) throw new Error("Fallback passwords did not match");
    if (fallbackPassword === authPassword) {
      throw new Error(
        "Auth and fallback passwords must differ — a captured operational password must not also decrypt the recovery key.",
      );
    }

    const { authAddress, fallbackAddress } = await generateKeystores(opts.dir, authPassword, fallbackPassword);
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
  .description("Deploy a new VorkaVault clone with this drive's auth/fallback keys")
  .action(async (factoryAddress: string) => {
    const opts = program.opts();
    const { authAddress, fallbackAddress } = await readAddressManifest(opts.dir);
    const provider = await getValidatedProvider(activeChain());
    const broadcaster = await requireBroadcaster(provider);

    const vaultAddress = await createVault(factoryAddress, fallbackAddress, authAddress, broadcaster);
    console.log(`Vault deployed: ${vaultAddress}`);
  });

program
  .command("withdraw <vaultAddress> <token> <amount>")
  .description("Sign and broadcast a withdraw. token: address(0) for native ETH/CFX, or an ERC20 address")
  .action(async (vaultAddress: string, token: string, amount: string) => {
    const opts = program.opts();
    const chain = activeChain();
    const provider = await getValidatedProvider(chain);
    const state = await getVaultState(provider, vaultAddress);
    const amountWei = await parseTokenAmount(provider, token, amount);

    console.log(`This withdraws ${amount} (token ${token}) to owner: ${state.owner}`);
    const { confirmed } = await prompts({ type: "confirm", name: "confirmed", message: "Sign and broadcast?" });
    if (!confirmed) return;

    const password = await askPassword();
    const auth = await unlockAuthKeystore(opts.dir, password);
    const deadline = await signingDeadline(provider);
    const signature = await signWithdraw(
      auth,
      { chainId: chain.chainId, vaultAddress },
      token,
      amountWei,
      deadline,
      state.operationalNonce,
    );

    const broadcaster = await requireBroadcaster(provider);
    const txHash = await submitWithdraw(vaultAddress, token, amountWei, deadline, signature, broadcaster);
    console.log(`Broadcast: ${txHash}`);
  });

program
  .command("list-actions")
  .description("List the curated actions execute() can be used against")
  .option("--registry <path>", "path to the actions registry", path.join(process.cwd(), "vorka-actions.json"))
  .action(async (cmdOpts) => {
    activeChain(); // validates --chain, throws on an unrecognized name
    const chainName = program.opts().chain as string;
    const actions = await loadRegistry(cmdOpts.registry);
    for (const action of actions.filter((a) => a.chain === chainName)) {
      console.log(`${action.id}: ${action.description} (${action.target})`);
    }
  });

program
  .command("execute <vaultAddress> <actionId> <argsJson>")
  .description('Build, review, sign, and broadcast a curated execute() call. argsJson: e.g. \'["0xSpender", "1000"]\'')
  .option("--registry <path>", "path to the actions registry", path.join(process.cwd(), "vorka-actions.json"))
  .option("--value <ether>", "native value to send with the call", "0")
  .action(async (vaultAddress: string, actionId: string, argsJson: string, cmdOpts) => {
    const opts = program.opts();
    const chain = activeChain();
    const actions = await loadRegistry(cmdOpts.registry);
    const action = findAction(actions, actionId);
    if (!action) throw new Error(`Unknown action "${actionId}". Run list-actions to see what's available.`);
    if (action.chain !== opts.chain) {
      throw new Error(
        `Action "${actionId}" is registered for chain "${action.chain}", not "${opts.chain}". ` +
          "Pass --chain to match, or double-check the registry entry.",
      );
    }

    const args = JSON.parse(argsJson) as unknown[];
    const data = encodeActionCall(action, args);
    const { summary, warnings } = reviewActionCall(action, data);

    console.log(summary);
    for (const warning of warnings) console.warn(`WARNING: ${warning}`);

    const { confirmed } = await prompts({ type: "confirm", name: "confirmed", message: "Sign and broadcast this call?" });
    if (!confirmed) return;

    const provider = await getValidatedProvider(chain);
    const state = await getVaultState(provider, vaultAddress);
    const value = parseEther(cmdOpts.value);

    const password = await askPassword();
    const auth = await unlockAuthKeystore(opts.dir, password);
    const deadline = await signingDeadline(provider);
    const signature = await signExecute(
      auth,
      { chainId: chain.chainId, vaultAddress },
      action.target,
      value,
      data,
      deadline,
      state.operationalNonce,
    );

    const broadcaster = await requireBroadcaster(provider);
    const txHash = await submitExecute(vaultAddress, action.target, value, data, deadline, signature, broadcaster);
    console.log(`Broadcast: ${txHash}`);
  });

async function rotate(vaultAddress: string, field: "auth" | "fallback", newAddress: string, dir: string) {
  const chain = activeChain();
  const provider = await getValidatedProvider(chain);
  const state = await getVaultState(provider, vaultAddress);

  const password = await askPassword("Fallback key password");
  const fallback = await unlockFallbackKeystore(dir, password);

  const newOwner = ZeroAddress;
  const newFallback = field === "fallback" ? newAddress : ZeroAddress;
  const newAuth = field === "auth" ? newAddress : ZeroAddress;
  const deadline = await signingDeadline(provider);

  const signature = await signModifyIdentity(
    fallback,
    { chainId: chain.chainId, vaultAddress },
    newOwner,
    newFallback,
    newAuth,
    deadline,
    state.governanceNonce,
  );

  const broadcaster = await requireBroadcaster(provider);
  const txHash = await submitModifyIdentity(
    vaultAddress,
    newOwner,
    newFallback,
    newAuth,
    deadline,
    signature,
    broadcaster,
  );
  console.log(`Broadcast: ${txHash}`);
}

program
  .command("rotate-auth <vaultAddress> <newAuthAddress>")
  .description("Replace the operational (USB) key — signed by the fallback key")
  .action(async (vaultAddress: string, newAuthAddress: string) => {
    const opts = program.opts();
    await rotate(vaultAddress, "auth", newAuthAddress, opts.dir);
  });

program
  .command("rotate-fallback <vaultAddress> <newFallbackAddress>")
  .description("Replace the recovery root key — signed by the current fallback key")
  .action(async (vaultAddress: string, newFallbackAddress: string) => {
    const opts = program.opts();
    await rotate(vaultAddress, "fallback", newFallbackAddress, opts.dir);
  });

program.parseAsync(process.argv).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
