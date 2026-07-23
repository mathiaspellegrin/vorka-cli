import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { generateKeystores, unlockKeystores } from "../src/keystore.js";

describe("keystore", () => {
  it("round-trips through encrypt/decrypt with the correct password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      const { authAddress, fallbackAddress } = await generateKeystores(dir, "correct horse battery staple");
      const { auth, fallback } = await unlockKeystores(dir, "correct horse battery staple");
      expect(auth.address).toBe(authAddress);
      expect(fallback.address).toBe(fallbackAddress);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects the wrong password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, "correct password");
      await expect(unlockKeystores(dir, "wrong password")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
