import { describe, expect, it } from "vitest";
import type { JsonRpcProvider } from "ethers";
import { signingDeadline, validateProvider } from "../src/chain.js";

describe("chain validation", () => {
  it("rejects an RPC whose reported chain ID does not match configuration", async () => {
    const provider = { getNetwork: async () => ({ chainId: 71n }) } as unknown as JsonRpcProvider;
    await expect(validateProvider(provider, 1030)).rejects.toThrow(/RPC chain ID mismatch/);
  });

  it("derives signature deadlines from the chain clock", async () => {
    // Raw eth_getBlockByNumber, not provider.getBlock("latest") — see chain.ts's signingDeadline
    // for why (ethers' cached getBlock can return a stale timestamp after an out-of-band clock
    // jump, e.g. the e2e smoke test's evm_increaseTime). Real RPC responses hex-encode timestamp.
    const provider = { send: async () => ({ timestamp: "0x3e8" }) } as unknown as JsonRpcProvider;
    await expect(signingDeadline(provider, 300)).resolves.toBe(1_300n);
  });
});
