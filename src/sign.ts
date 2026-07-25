import type { Wallet, HDNodeWallet } from "ethers";
import { executeTypedData, freezeTypedData, modifyIdentityTypedData, withdrawTypedData, type VaultDomain } from "./domain.js";

type Signer = Wallet | HDNodeWallet;

/**
 * Signs with `signer` and discards nothing extra — the caller is responsible
 * for having decrypted `signer` for this one operation and letting it go
 * afterwards (see keystore.ts). Ethers' `signTypedData` computes the same
 * digest as Solidity's `_hashTypedDataV4` for the given domain/types/value.
 */
export async function signWithdraw(
  signer: Signer,
  domainParams: VaultDomain,
  token: string,
  amount: bigint,
  deadline: bigint,
  nonce: bigint,
): Promise<string> {
  const { domain, types, value } = withdrawTypedData(domainParams, token, amount, deadline, nonce);
  return signer.signTypedData(domain, types, value);
}

export async function signExecute(
  signer: Signer,
  domainParams: VaultDomain,
  target: string,
  value: bigint,
  data: string,
  deadline: bigint,
  nonce: bigint,
): Promise<string> {
  const typed = executeTypedData(domainParams, target, value, data, deadline, nonce);
  return signer.signTypedData(typed.domain, typed.types, typed.value);
}

export async function signModifyIdentity(
  signer: Signer,
  domainParams: VaultDomain,
  newOwner: string,
  newFallback: string,
  newAuth: string,
  deadline: bigint,
  nonce: bigint,
): Promise<string> {
  const typed = modifyIdentityTypedData(domainParams, newOwner, newFallback, newAuth, deadline, nonce);
  return signer.signTypedData(typed.domain, typed.types, typed.value);
}

export async function signFreeze(
  signer: Signer,
  domainParams: VaultDomain,
  deadline: bigint,
  nonce: bigint,
): Promise<string> {
  const typed = freezeTypedData(domainParams, deadline, nonce);
  return signer.signTypedData(typed.domain, typed.types, typed.value);
}
