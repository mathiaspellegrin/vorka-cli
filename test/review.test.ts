import { describe, expect, it, vi } from "vitest";
import { MaxUint256, keccak256, type JsonRpcProvider } from "ethers";
import { encodeActionCall, verifyAndSimulateAction, type RegistryAction } from "../src/registry.js";
import { reviewActionCall } from "../src/review.js";

const action: RegistryAction = {
  id: "test-approve",
  description: "test approve action",
  chain: "local",
  target: "0x000000000000000000000000000000000000dead",
  codeHash: `0x${"11".repeat(32)}`,
  abi: ["function approve(address spender, uint256 amount) returns (bool)"],
  function: "approve",
};

const spender = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

describe("review", () => {
  it("flags an unbounded approval", () => {
    const data = encodeActionCall(action, [spender, MaxUint256]);
    const { warnings } = reviewActionCall(action, data);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/unbounded/i);
  });

  it("passes a normal bounded amount", () => {
    const data = encodeActionCall(action, [spender, 1000n]);
    const { warnings } = reviewActionCall(action, data);
    expect(warnings).toHaveLength(0);
  });
});

describe("curated target verification", () => {
  it("rejects runtime bytecode drift before simulation", async () => {
    const provider = {
      getCode: vi.fn().mockResolvedValue("0x6000"),
      call: vi.fn(),
    } as unknown as JsonRpcProvider;

    await expect(
      verifyAndSimulateAction(provider, spender, action, 0n, encodeActionCall(action, [spender, 1n])),
    ).rejects.toThrow(/bytecode changed/i);
    expect(provider.call).not.toHaveBeenCalled();
  });

  it("simulates from the vault after bytecode verification", async () => {
    const code = "0x6000";
    const verifiedAction = { ...action, codeHash: keccak256(code) };
    const provider = {
      getCode: vi.fn().mockResolvedValue(code),
      call: vi.fn().mockResolvedValue("0x"),
    } as unknown as JsonRpcProvider;
    const data = encodeActionCall(verifiedAction, [spender, 1n]);

    await verifyAndSimulateAction(provider, spender, verifiedAction, 0n, data);
    expect(provider.call).toHaveBeenCalledWith({ from: spender, to: verifiedAction.target, value: 0n, data });
  });
});
