import { describe, expect, it } from "vitest";
import { MaxUint256 } from "ethers";
import { encodeActionCall, type RegistryAction } from "../src/registry.js";
import { reviewActionCall } from "../src/review.js";

const action: RegistryAction = {
  id: "test-approve",
  description: "test approve action",
  target: "0x000000000000000000000000000000000000dead",
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
