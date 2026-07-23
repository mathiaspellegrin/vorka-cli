import { Contract, JsonRpcProvider, type Wallet, type HDNodeWallet } from "ethers";

export interface ChainConfig {
  rpc: string;
  chainId: number;
}

/**
 * Named chains the CLI can target. Vorka launches on Conflux; each
 * additional chain is expected to arrive through a direct partnership with
 * a project on that chain, not generic multi-chain support — see
 * docs/VORKA.md, "Multi-chain and partnerships". Adding one is just a new
 * entry here.
 */
export const CHAINS: Record<string, ChainConfig> = {
  "conflux-mainnet": { rpc: "https://evm.confluxrpc.com", chainId: 1030 },
  "conflux-testnet": { rpc: "https://evmtestnet.confluxrpc.com", chainId: 71 },
};

/** Only the pieces of VorkaVault/VorkaVaultFactory the CLI actually touches. */
const VORKA_VAULT_ABI = [
  "function owner() view returns (address)",
  "function fallbackAddress() view returns (address)",
  "function authAddress() view returns (address)",
  "function nonce() view returns (uint256)",
  "function withdraw(address token, uint256 amount, bytes signature)",
  "function execute(address target, uint256 value, bytes data, bytes signature) returns (bytes)",
  "function modifyIdentity(address newOwner, address newFallback, address newAuth, bytes signature)",
];

const VORKA_VAULT_FACTORY_ABI = [
  "function createVault(address fallbackAddr, address authAddr) returns (address)",
  "function vaultOf(address creator) view returns (address)",
];

type Signer = Wallet | HDNodeWallet;

export interface VaultState {
  owner: string;
  fallbackAddress: string;
  authAddress: string;
  nonce: bigint;
}

export function getProvider(rpcUrl: string): JsonRpcProvider {
  return new JsonRpcProvider(rpcUrl);
}

function vaultContract(vaultAddress: string, runner: JsonRpcProvider | Signer): Contract {
  return new Contract(vaultAddress, VORKA_VAULT_ABI, runner);
}

function factoryContract(factoryAddress: string, runner: JsonRpcProvider | Signer): Contract {
  return new Contract(factoryAddress, VORKA_VAULT_FACTORY_ABI, runner);
}

export async function getVaultState(provider: JsonRpcProvider, vaultAddress: string): Promise<VaultState> {
  const vault = vaultContract(vaultAddress, provider);
  const [owner, fallbackAddress, authAddress, nonce] = await Promise.all([
    vault.owner(),
    vault.fallbackAddress(),
    vault.authAddress(),
    vault.nonce(),
  ]);
  return { owner, fallbackAddress, authAddress, nonce };
}

/**
 * `broadcaster` pays Conflux gas for every function below — it is a separate,
 * low-stakes account from `authAddress`/`fallbackAddress` (see docs/VORKA.md).
 * It must already be connected to a provider (`new Wallet(key, provider)`).
 */
export async function createVault(
  factoryAddress: string,
  fallbackAddr: string,
  authAddr: string,
  broadcaster: Signer,
): Promise<string> {
  const factory = factoryContract(factoryAddress, broadcaster);
  const tx = await factory.createVault(fallbackAddr, authAddr);
  await tx.wait();
  return factory.vaultOf(broadcaster.address);
}

export async function submitWithdraw(
  vaultAddress: string,
  token: string,
  amount: bigint,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.withdraw(token, amount, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function submitExecute(
  vaultAddress: string,
  target: string,
  value: bigint,
  data: string,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.execute(target, value, data, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function submitModifyIdentity(
  vaultAddress: string,
  newOwner: string,
  newFallback: string,
  newAuth: string,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.modifyIdentity(newOwner, newFallback, newAuth, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}
