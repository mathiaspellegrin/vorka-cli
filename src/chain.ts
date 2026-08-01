import { Contract, JsonRpcProvider, id, type Wallet, type HDNodeWallet } from "ethers";

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
  // Local Anvil devnet (`anvil`'s default chain id) — for end-to-end testing
  // against a real deployment, not a real chain. See companion/scripts/e2e-smoke.sh.
  local: { rpc: "http://127.0.0.1:8545", chainId: 31337 },
};

export const DEFAULT_SIGNATURE_VALIDITY_SECONDS = 30 * 60;
const RETAIL_IMPLEMENTATION_ID = id("VorkaVault.retail.v1");

/** Only the pieces of VorkaVault/VorkaVaultFactory the CLI actually touches. */
const VORKA_VAULT_ABI = [
  "function owner() view returns (address)",
  "function fallbackAddress() view returns (address)",
  "function authAddress() view returns (address)",
  "function operationalNonce() view returns (uint256)",
  "function governanceNonce() view returns (uint256)",
  "function emergencyNonce() view returns (uint256)",
  "function frozen() view returns (bool)",
  "function withdraw(address token, uint256 amount, uint256 deadline, bytes signature)",
  "function execute(address target, uint256 value, bytes data, uint256 deadline, bytes signature) returns (bytes)",
  "function modifyIdentity(address newOwner, address newFallback, address newAuth, uint256 deadline, bytes signature)",
  "function freeze(uint256 deadline, bytes signature)",
];

const VORKA_VAULT_FACTORY_ABI = [
  "function createVault(address owner, address fallbackAddress, address authAddress, bytes32 userSalt) returns (address)",
  "function vaultOf(address owner, bytes32 userSalt) view returns (address)",
  "function predictVaultAddress(address owner, address fallbackAddress, address authAddress, bytes32 userSalt) view returns (address)",
  "function implementation() view returns (address)",
];

const IMPLEMENTATION_ABI = ["function implementationId() view returns (bytes32)"];

type Signer = Wallet | HDNodeWallet;

export interface VaultState {
  owner: string;
  fallbackAddress: string;
  authAddress: string;
  /** Consumed by withdraw/execute. Independent from governanceNonce — see docs/VORKA.md. */
  operationalNonce: bigint;
  /** Consumed by modifyIdentity/modifyGovernance. Independent from operationalNonce. */
  governanceNonce: bigint;
  emergencyNonce: bigint;
  frozen: boolean;
}

export function getProvider(rpcUrl: string): JsonRpcProvider {
  return new JsonRpcProvider(rpcUrl);
}

export async function validateProvider(provider: JsonRpcProvider, expectedChainId: number): Promise<void> {
  const network = await provider.getNetwork();
  if (network.chainId !== BigInt(expectedChainId)) {
    throw new Error(`RPC chain ID mismatch: expected ${expectedChainId}, received ${network.chainId}`);
  }
}

export async function getValidatedProvider(chain: ChainConfig): Promise<JsonRpcProvider> {
  const provider = getProvider(chain.rpc);
  await validateProvider(provider, chain.chainId);
  return provider;
}

export async function signingDeadline(
  provider: JsonRpcProvider,
  validitySeconds = DEFAULT_SIGNATURE_VALIDITY_SECONDS,
): Promise<bigint> {
  // Raw RPC call, not provider.getBlock("latest") — ethers' cached block can go stale relative to
  // true chain time (confirmed directly: after an out-of-band clock jump, getBlock("latest") kept
  // returning the pre-jump timestamp while eth_getBlockByNumber returned the correct one), which
  // would compute an already-expired deadline. Only reproducible against a devnet whose clock can
  // jump out of band (this is what companion/scripts/e2e-smoke.ts does to clear the governance
  // cooldown); a real chain's block time only ever moves forward through normal polling. Fixing at
  // the source rather than only in the test script, since the raw call is just as cheap either way.
  const block = await provider.send("eth_getBlockByNumber", ["latest", false]);
  if (!block?.timestamp) throw new Error("RPC did not return a latest block");
  return BigInt(block.timestamp) + BigInt(validitySeconds);
}

function vaultContract(vaultAddress: string, runner: JsonRpcProvider | Signer): Contract {
  return new Contract(vaultAddress, VORKA_VAULT_ABI, runner);
}

function factoryContract(factoryAddress: string, runner: JsonRpcProvider | Signer): Contract {
  return new Contract(factoryAddress, VORKA_VAULT_FACTORY_ABI, runner);
}

export async function getVaultState(provider: JsonRpcProvider, vaultAddress: string): Promise<VaultState> {
  const vault = vaultContract(vaultAddress, provider);
  const [owner, fallbackAddress, authAddress, operationalNonce, governanceNonce, emergencyNonce, frozen] = await Promise.all([
    vault.owner(),
    vault.fallbackAddress(),
    vault.authAddress(),
    vault.operationalNonce(),
    vault.governanceNonce(),
    vault.emergencyNonce(),
    vault.frozen(),
  ]);
  return { owner, fallbackAddress, authAddress, operationalNonce, governanceNonce, emergencyNonce, frozen };
}

/**
 * `broadcaster` pays Conflux gas for every function below — it is a separate,
 * low-stakes account from `authAddress`/`fallbackAddress` (see docs/VORKA.md).
 * It must already be connected to a provider (`new Wallet(key, provider)`).
 */
export async function createVault(
  factoryAddress: string,
  owner: string,
  fallbackAddr: string,
  authAddr: string,
  userSalt: string,
  broadcaster: Signer,
): Promise<string> {
  const factory = factoryContract(factoryAddress, broadcaster);
  const implementationAddress: string = await factory.implementation();
  const implementation = new Contract(implementationAddress, IMPLEMENTATION_ABI, broadcaster);
  if ((await implementation.implementationId()) !== RETAIL_IMPLEMENTATION_ID) {
    throw new Error("Factory points to an unexpected VorkaVault implementation edition");
  }
  const predicted: string = await factory.predictVaultAddress(owner, fallbackAddr, authAddr, userSalt);
  const tx = await factory.createVault(owner, fallbackAddr, authAddr, userSalt);
  await tx.wait();
  const deployed: string = await factory.vaultOf(owner, userSalt);
  if (deployed !== predicted) throw new Error(`Factory deployed ${deployed}, expected ${predicted}`);
  return deployed;
}

export async function submitFreeze(
  vaultAddress: string,
  deadline: bigint,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.freeze(deadline, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function submitWithdraw(
  vaultAddress: string,
  token: string,
  amount: bigint,
  deadline: bigint,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.withdraw(token, amount, deadline, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function estimateWithdrawFee(
  provider: JsonRpcProvider,
  vaultAddress: string,
  token: string,
  amount: bigint,
  deadline: bigint,
  signature: string,
  sender: string,
): Promise<{ gasLimit: bigint; maxFeePerGas: bigint; estimatedFee: bigint }> {
  const vault = vaultContract(vaultAddress, provider);
  const gasLimit: bigint = await vault.withdraw.estimateGas(token, amount, deadline, signature, { from: sender });
  const feeData = await provider.getFeeData();
  const maxFeePerGas = feeData.maxFeePerGas ?? feeData.gasPrice;
  if (maxFeePerGas === null) throw new Error("RPC did not return gas pricing");
  return { gasLimit, maxFeePerGas, estimatedFee: gasLimit * maxFeePerGas };
}

export async function submitExecute(
  vaultAddress: string,
  target: string,
  value: bigint,
  data: string,
  deadline: bigint,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.execute(target, value, data, deadline, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function submitModifyIdentity(
  vaultAddress: string,
  newOwner: string,
  newFallback: string,
  newAuth: string,
  deadline: bigint,
  signature: string,
  broadcaster: Signer,
): Promise<string> {
  const vault = vaultContract(vaultAddress, broadcaster);
  const tx = await vault.modifyIdentity(newOwner, newFallback, newAuth, deadline, signature);
  const receipt = await tx.wait();
  return receipt.hash;
}
