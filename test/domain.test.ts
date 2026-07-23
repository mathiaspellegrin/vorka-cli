import { describe, expect, it } from "vitest";
import { AbiCoder, TypedDataEncoder, concat, keccak256, toUtf8Bytes } from "ethers";
import { executeTypedData, modifyIdentityTypedData, withdrawTypedData } from "../src/domain.js";

/**
 * These tests independently re-derive the EIP-712 digest using the exact
 * formula `VorkaVaultBase`/`VorkaVault` use on-chain (domain separator +
 * struct hash + "\x19\x01" prefix — see src/VorkaVaultBase.sol,
 * src/VorkaVault.sol), then assert that ethers' `TypedDataEncoder` — the same
 * machinery `domain.ts`/`sign.ts` use for real signing — produces an
 * identical digest for the same inputs. A mismatch here means every
 * signature this CLI produces would be rejected on-chain.
 */

const CHAIN_ID = 1030;
const VAULT_ADDRESS = "0x1234567890123456789012345678901234567890";

const EIP712_DOMAIN_TYPEHASH = keccak256(
  toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
);

function rawDomainSeparator(): string {
  return keccak256(
    AbiCoder.defaultAbiCoder().encode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [
        EIP712_DOMAIN_TYPEHASH,
        keccak256(toUtf8Bytes("VorkaVault")),
        keccak256(toUtf8Bytes("1")),
        CHAIN_ID,
        VAULT_ADDRESS,
      ],
    ),
  );
}

function rawDigest(structHash: string): string {
  return keccak256(concat(["0x1901", rawDomainSeparator(), structHash]));
}

describe("domain — matches Solidity's _hashTypedDataV4 exactly", () => {
  it("Withdraw", () => {
    const WITHDRAW_TYPEHASH = keccak256(toUtf8Bytes("Withdraw(address token,uint256 amount,uint256 nonce)"));
    const token = "0x000000000000000000000000000000000000dead";
    const amount = 1_000_000_000_000_000_000n;
    const nonce = 0n;

    const structHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "uint256"],
        [WITHDRAW_TYPEHASH, token, amount, nonce],
      ),
    );
    const expected = rawDigest(structHash);

    const { domain, types, value } = withdrawTypedData({ chainId: CHAIN_ID, vaultAddress: VAULT_ADDRESS }, token, amount, nonce);
    expect(TypedDataEncoder.hash(domain, types, value)).toBe(expected);
  });

  it("Execute", () => {
    const EXECUTE_TYPEHASH = keccak256(
      toUtf8Bytes("Execute(address target,uint256 value,bytes32 dataHash,uint256 nonce)"),
    );
    const target = "0x000000000000000000000000000000000000aaaa";
    const value = 0n;
    const data = "0x1234";
    const nonce = 5n;

    const structHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "uint256", "bytes32", "uint256"],
        [EXECUTE_TYPEHASH, target, value, keccak256(data), nonce],
      ),
    );
    const expected = rawDigest(structHash);

    const typed = executeTypedData({ chainId: CHAIN_ID, vaultAddress: VAULT_ADDRESS }, target, value, data, nonce);
    expect(TypedDataEncoder.hash(typed.domain, typed.types, typed.value)).toBe(expected);
  });

  it("ModifyIdentity", () => {
    const MODIFY_IDENTITY_TYPEHASH = keccak256(
      toUtf8Bytes("ModifyIdentity(address newOwner,address newFallback,address newAuth,uint256 nonce)"),
    );
    const newOwner = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const newFallback = "0xcccccccccccccccccccccccccccccccccccccccc";
    const newAuth = "0xdddddddddddddddddddddddddddddddddddddddd";
    const nonce = 2n;

    const structHash = keccak256(
      AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "address", "address", "address", "uint256"],
        [MODIFY_IDENTITY_TYPEHASH, newOwner, newFallback, newAuth, nonce],
      ),
    );
    const expected = rawDigest(structHash);

    const typed = modifyIdentityTypedData({ chainId: CHAIN_ID, vaultAddress: VAULT_ADDRESS }, newOwner, newFallback, newAuth, nonce);
    expect(TypedDataEncoder.hash(typed.domain, typed.types, typed.value)).toBe(expected);
  });
});
