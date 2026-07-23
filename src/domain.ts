import { keccak256, type TypedDataDomain, type TypedDataField } from "ethers";

/**
 * EIP-712 domain/type builders that mirror the Solidity side field-for-field:
 * - domain name/version: VorkaVaultBase's `EIP712("VorkaVault", "1")` (src/VorkaVault.sol)
 * - struct shapes: VorkaVaultBase.WITHDRAW_TYPEHASH / EXECUTE_TYPEHASH and
 *   VorkaVault.MODIFY_IDENTITY_TYPEHASH (src/VorkaVaultBase.sol, src/VorkaVault.sol)
 *
 * This is the single source of truth on the app side — if a typehash ever changes
 * in the Solidity contracts, the corresponding type below must change identically,
 * or every signature this CLI produces becomes invalid on-chain.
 */

export interface VaultDomain {
  chainId: number;
  vaultAddress: string;
}

const WITHDRAW_TYPES: Record<string, TypedDataField[]> = {
  Withdraw: [
    { name: "token", type: "address" },
    { name: "amount", type: "uint256" },
    { name: "nonce", type: "uint256" },
  ],
};

const EXECUTE_TYPES: Record<string, TypedDataField[]> = {
  // Solidity hashes `keccak256(data)` into the struct, not the raw bytes — this
  // type must declare `dataHash` as `bytes32`, matching EXECUTE_TYPEHASH exactly.
  Execute: [
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "dataHash", type: "bytes32" },
    { name: "nonce", type: "uint256" },
  ],
};

const MODIFY_IDENTITY_TYPES: Record<string, TypedDataField[]> = {
  ModifyIdentity: [
    { name: "newOwner", type: "address" },
    { name: "newFallback", type: "address" },
    { name: "newAuth", type: "address" },
    { name: "nonce", type: "uint256" },
  ],
};

export function domainFor({ chainId, vaultAddress }: VaultDomain): TypedDataDomain {
  return {
    name: "VorkaVault",
    version: "1",
    chainId,
    verifyingContract: vaultAddress,
  };
}

export function withdrawTypedData(domain: VaultDomain, token: string, amount: bigint, nonce: bigint) {
  return {
    domain: domainFor(domain),
    types: WITHDRAW_TYPES,
    value: { token, amount, nonce },
  };
}

export function executeTypedData(domain: VaultDomain, target: string, value: bigint, data: string, nonce: bigint) {
  return {
    domain: domainFor(domain),
    types: EXECUTE_TYPES,
    value: { target, value, dataHash: keccak256(data), nonce },
  };
}

export function modifyIdentityTypedData(
  domain: VaultDomain,
  newOwner: string,
  newFallback: string,
  newAuth: string,
  nonce: bigint,
) {
  return {
    domain: domainFor(domain),
    types: MODIFY_IDENTITY_TYPES,
    value: { newOwner, newFallback, newAuth, nonce },
  };
}
