import { Interface, MaxUint256 } from "ethers";
import type { RegistryAction } from "./registry.js";

export interface ReviewResult {
  summary: string;
  warnings: string[];
}

/**
 * Decodes `data` against the action's own ABI fragment into a plain-language
 * summary, and flags any uint256 argument set to the max value — the classic
 * unlimited-approval pattern drainer scams rely on. Heuristic, not a full
 * transaction simulation (see docs/FLUXPAD.md — that's a documented fast-follow).
 */
export function reviewActionCall(action: RegistryAction, data: string): ReviewResult {
  const iface = new Interface(action.abi);
  const fragment = iface.getFunction(action.function);
  if (!fragment) {
    throw new Error(`Unknown function "${action.function}" in registry action "${action.id}"`);
  }

  const decoded = iface.decodeFunctionData(fragment, data);
  const warnings: string[] = [];

  fragment.inputs.forEach((input, i) => {
    if (input.type === "uint256" && decoded[i] === MaxUint256) {
      warnings.push(
        `Parameter "${input.name || i}" is unbounded (max uint256) — the pattern drainer scams rely on for unlimited-spend approvals. Prefer an exact amount.`,
      );
    }
  });

  const argSummary = fragment.inputs.map((input, i) => `${input.name || `arg${i}`}=${decoded[i]?.toString()}`).join(", ");

  return {
    summary: `${action.description}\nTarget: ${action.target}\nCall: ${action.function}(${argSummary})`,
    warnings,
  };
}
