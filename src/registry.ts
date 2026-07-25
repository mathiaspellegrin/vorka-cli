import { Interface, getAddress, keccak256, type JsonRpcProvider } from "ethers";
import { promises as fs } from "node:fs";

/**
 * A curated, vetted action: a specific target contract + ABI fragment the app
 * is willing to build an `execute()` call against. There is no "paste a raw
 * target + calldata" path in the default flow — see docs/VORKA.md, "No web,
 * no WalletConnect". For this pass the registry is a bundled local file; a
 * live Vorka-signed registry is a documented fast-follow, not built here.
 */
export interface RegistryAction {
  id: string;
  description: string;
  /** Key into chain.ts's CHAINS — which chain `target` actually lives on. */
  chain: string;
  target: string;
  /** Expected runtime bytecode hash; prevents a changed target from silently retaining trust. */
  codeHash: string;
  abi: string[];
  function: string;
}

export async function loadRegistry(registryPath: string): Promise<RegistryAction[]> {
  const raw = await fs.readFile(registryPath, "utf8");
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("Action registry must be an array");
  return parsed.map((entry, index) => {
    if (!entry || typeof entry !== "object") throw new Error(`Invalid action registry entry ${index}`);
    const action = entry as Record<string, unknown>;
    for (const field of ["id", "description", "chain", "target", "codeHash", "function"]) {
      if (typeof action[field] !== "string") throw new Error(`Invalid action ${index} field: ${field}`);
    }
    if (!Array.isArray(action.abi) || !action.abi.every((fragment) => typeof fragment === "string")) {
      throw new Error(`Invalid action ${index} ABI`);
    }
    const normalized = action as unknown as RegistryAction;
    normalized.target = getAddress(normalized.target);
    if (!/^0x[0-9a-fA-F]{64}$/.test(normalized.codeHash)) throw new Error(`Invalid action ${index} codeHash`);
    // Parse the selected function now so malformed registry entries fail before signing.
    const fragment = new Interface(normalized.abi).getFunction(normalized.function);
    if (!fragment) throw new Error(`Unknown function in action ${normalized.id}`);
    return normalized;
  });
}

export function findAction(actions: RegistryAction[], id: string): RegistryAction | undefined {
  return actions.find((action) => action.id === id);
}

export function encodeActionCall(action: RegistryAction, args: unknown[]): string {
  const iface = new Interface(action.abi);
  return iface.encodeFunctionData(action.function, args);
}

export async function verifyAndSimulateAction(
  provider: JsonRpcProvider,
  vaultAddress: string,
  action: RegistryAction,
  value: bigint,
  data: string,
): Promise<void> {
  const code = await provider.getCode(action.target);
  if (code === "0x") throw new Error(`Curated target ${action.target} has no deployed code`);
  const actualHash = keccak256(code);
  if (actualHash.toLowerCase() !== action.codeHash.toLowerCase()) {
    throw new Error(`Curated target bytecode changed: expected ${action.codeHash}, received ${actualHash}`);
  }
  await provider.call({ from: vaultAddress, to: action.target, value, data });
}
