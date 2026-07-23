import { describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  generateKeystores,
  readAddressManifest,
  unlockAuthKeystore,
  unlockFallbackKeystore,
} from "../src/keystore.js";

describe("keystore", () => {
  it("round-trips through encrypt/decrypt with each key's own password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      const { authAddress, fallbackAddress } = await generateKeystores(dir, "auth password", "fallback password");
      const auth = await unlockAuthKeystore(dir, "auth password");
      const fallback = await unlockFallbackKeystore(dir, "fallback password");
      expect(auth.address).toBe(authAddress);
      expect(fallback.address).toBe(fallbackAddress);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects the wrong password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, "auth password", "fallback password");
      await expect(unlockAuthKeystore(dir, "wrong password")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not let the auth password decrypt the fallback keystore, or vice versa", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, "auth password", "fallback password");
      await expect(unlockFallbackKeystore(dir, "auth password")).rejects.toThrow();
      await expect(unlockAuthKeystore(dir, "fallback password")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exposes public addresses via the manifest without any password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      const { authAddress, fallbackAddress } = await generateKeystores(dir, "auth password", "fallback password");
      const manifest = await readAddressManifest(dir);
      expect(manifest.authAddress).toBe(authAddress);
      expect(manifest.fallbackAddress).toBe(fallbackAddress);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
