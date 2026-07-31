import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  generateKeystores,
  readAddressManifest,
  unlockAuthKeystore,
  unlockFallbackKeystore,
  backupKeystores,
  ADDRESS_MANIFEST_FILENAME,
  AUTH_KEYSTORE_FILENAME,
  FALLBACK_KEYSTORE_FILENAME,
  generateSplitKeystores,
  getDeviceRole,
  generateReplacementAuth,
  VORKA_DATA_DIRECTORY,
} from "../src/keystore.js";

const AUTH_PASSWORD = "cobalt river lantern meadow 47";
const FALLBACK_PASSWORD = "velvet orbit cedar compass 93";

describe("keystore", () => {
  it("splits operational and recovery secrets across two devices", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vorka-split-"));
    const primary = path.join(root, "primary");
    const recovery = path.join(root, "recovery");
    try {
      await Promise.all([mkdir(primary), mkdir(recovery)]);
      const manifest = await generateSplitKeystores(primary, recovery, AUTH_PASSWORD, AUTH_PASSWORD);
      expect(await getDeviceRole(primary)).toBe("primary");
      expect(await getDeviceRole(recovery)).toBe("recovery");
      const encryptedAuth = JSON.parse(await readFile(path.join(primary, VORKA_DATA_DIRECTORY, AUTH_KEYSTORE_FILENAME), "utf8"));
      expect(encryptedAuth.Crypto?.kdf === "scrypt" || encryptedAuth.crypto?.kdf === "scrypt").toBe(true);
      expect(Number(encryptedAuth.Crypto?.kdfparams?.n ?? encryptedAuth.crypto?.kdfparams?.n)).toBeGreaterThanOrEqual(131072);
      await expect(readFile(path.join(recovery, VORKA_DATA_DIRECTORY, FALLBACK_KEYSTORE_FILENAME))).resolves.toBeTruthy();
      await expect(readFile(path.join(primary, AUTH_KEYSTORE_FILENAME))).rejects.toThrow();
      await expect(readFile(path.join(primary, FALLBACK_KEYSTORE_FILENAME))).rejects.toThrow();
      await expect(readFile(path.join(recovery, AUTH_KEYSTORE_FILENAME))).rejects.toThrow();
      expect((await readAddressManifest(primary)).generationId).toBe(manifest.generationId);
      expect((await readAddressManifest(recovery)).generationId).toBe(manifest.generationId);
      expect((await unlockAuthKeystore(primary, AUTH_PASSWORD)).address).toBe(manifest.authAddress);
      expect((await unlockFallbackKeystore(recovery, AUTH_PASSWORD)).address).toBe(manifest.fallbackAddress);
      await expect(generateSplitKeystores(primary, primary, AUTH_PASSWORD, AUTH_PASSWORD)).rejects.toThrow(/different USB/);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("creates a replacement primary while retaining the recovery secret", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vorka-replace-"));
    const primary = path.join(root, "primary"), recovery = path.join(root, "recovery"), replacement = path.join(root, "replacement");
    try {
      await Promise.all([mkdir(primary), mkdir(recovery), mkdir(replacement)]);
      const original = await generateSplitKeystores(primary, recovery, AUTH_PASSWORD, FALLBACK_PASSWORD);
      const next = await generateReplacementAuth(replacement, recovery, "granite-signal-ember-forest-9274", FALLBACK_PASSWORD);
      expect(next.authAddress).not.toBe(original.authAddress);
      expect(next.fallbackAddress).toBe(original.fallbackAddress);
      expect((await readAddressManifest(recovery)).generationId).toBe(next.generationId);
      expect((await unlockFallbackKeystore(recovery, FALLBACK_PASSWORD)).address).toBe(original.fallbackAddress);
      expect(await getDeviceRole(replacement)).toBe("primary");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  it("round-trips through encrypt/decrypt with each key's own password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      const { authAddress, fallbackAddress } = await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      const auth = await unlockAuthKeystore(dir, AUTH_PASSWORD);
      const fallback = await unlockFallbackKeystore(dir, FALLBACK_PASSWORD);
      expect(auth.address).toBe(authAddress);
      expect(fallback.address).toBe(fallbackAddress);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects the wrong password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      await expect(unlockAuthKeystore(dir, "wrong password")).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("does not let the auth password decrypt the fallback keystore, or vice versa", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      await expect(unlockFallbackKeystore(dir, AUTH_PASSWORD)).rejects.toThrow();
      await expect(unlockAuthKeystore(dir, FALLBACK_PASSWORD)).rejects.toThrow();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exposes public addresses via the manifest without any password", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      const { authAddress, fallbackAddress } = await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      const manifest = await readAddressManifest(dir);
      expect(manifest.authAddress).toBe(authAddress);
      expect(manifest.fallbackAddress).toBe(fallbackAddress);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects weak and identical passwords", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await expect(generateKeystores(dir, "short", FALLBACK_PASSWORD)).rejects.toThrow(/16 characters/);
      await expect(generateKeystores(dir, "passwordpassword", FALLBACK_PASSWORD)).rejects.toThrow(/too easy/);
      await expect(generateKeystores(dir, AUTH_PASSWORD, AUTH_PASSWORD)).rejects.toThrow(/must differ/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rejects a tampered manifest or encrypted keystore", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "vorka-"));
    try {
      await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      const manifestPath = path.join(dir, ADDRESS_MANIFEST_FILENAME);
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      const mutations = [
        { ...manifest, format: "vorka-keystore-bundle-v2" },
        { ...manifest, generationId: `0x${"11".repeat(32)}` },
        { ...manifest, authAddress: "0x000000000000000000000000000000000000dEaD" },
        { ...manifest, fallbackAddress: "0x000000000000000000000000000000000000bEEF" },
        { ...manifest, authKeystoreHash: `0x${"22".repeat(32)}` },
        { ...manifest, fallbackKeystoreHash: `0x${"33".repeat(32)}` },
        { ...manifest, authSignature: manifest.fallbackSignature },
        { ...manifest, fallbackSignature: manifest.authSignature },
      ];
      for (const mutation of mutations) {
        await writeFile(manifestPath, JSON.stringify(mutation));
        await expect(readAddressManifest(dir)).rejects.toThrow();
      }

      await rm(dir, { recursive: true, force: true });
      await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      const authPath = path.join(dir, AUTH_KEYSTORE_FILENAME);
      await writeFile(authPath, `${await readFile(authPath, "utf8")} `);
      await expect(unlockAuthKeystore(dir, AUTH_PASSWORD)).rejects.toThrow(/does not match signed bundle/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("never overwrites an existing bundle or backup destination", async () => {
    const root = await mkdtemp(path.join(tmpdir(), "vorka-"));
    const dir = path.join(root, "source");
    const backup = path.join(root, "backup");
    try {
      await generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD);
      await expect(generateKeystores(dir, AUTH_PASSWORD, FALLBACK_PASSWORD)).rejects.toThrow(/Refusing to overwrite/);
      await backupKeystores(dir, backup);
      await expect(backupKeystores(dir, backup)).rejects.toThrow(/Refusing to overwrite/);
      const copied = await readAddressManifest(backup);
      const original = await readAddressManifest(dir);
      expect(copied.generationId).toBe(original.generationId);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
