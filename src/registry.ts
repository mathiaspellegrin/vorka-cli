import { Interface } from "ethers";
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
  target: string;
  abi: string[];
  function: string;
}

export async function loadRegistry(registryPath: string): Promise<RegistryAction[]> {
  const raw = await fs.readFile(registryPath, "utf8");
  return JSON.parse(raw) as RegistryAction[];
}

export function findAction(actions: RegistryAction[], id: string): RegistryAction | undefined {
  return actions.find((action) => action.id === id);
}

export function encodeActionCall(action: RegistryAction, args: unknown[]): string {
  const iface = new Interface(action.abi);
  return iface.encodeFunctionData(action.function, args);
}
