import { Wallet, type HDNodeWallet } from "ethers";
import { promises as fs } from "node:fs";
import path from "node:path";

export const AUTH_KEYSTORE_FILENAME = "vorka-auth.json";
export const FALLBACK_KEYSTORE_FILENAME = "vorka-fallback.json";
export const ADDRESS_MANIFEST_FILENAME = "vorka-addresses.json";

type AnyWallet = Wallet | HDNodeWallet;

export interface AddressManifest {
  authAddress: string;
  fallbackAddress: string;
}

/**
 * Generates fresh auth/fallback keypairs and writes both as standard Ethereum
 * V3 keystores (scrypt + AES, via ethers' own encryption) to `dir`, each
 * protected by its own password — a captured operational password (or a
 * copied keystore file) must not be enough to also decrypt the fallback key.
 * Also writes a plaintext manifest of the two public addresses: they aren't
 * secret, and having them on disk means commands that only need an address
 * (like `create-vault`) never have to decrypt a private key just to read one.
 */
export async function generateKeystores(
  dir: string,
  authPassword: string,
  fallbackPassword: string,
): Promise<AddressManifest> {
  const auth = Wallet.createRandom();
  const fallback = Wallet.createRandom();

  const authJson = await auth.encrypt(authPassword);
  const fallbackJson = await fallback.encrypt(fallbackPassword);
  const manifest: AddressManifest = { authAddress: auth.address, fallbackAddress: fallback.address };

  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, AUTH_KEYSTORE_FILENAME), authJson, "utf8");
  await fs.writeFile(path.join(dir, FALLBACK_KEYSTORE_FILENAME), fallbackJson, "utf8");
  await fs.writeFile(path.join(dir, ADDRESS_MANIFEST_FILENAME), JSON.stringify(manifest, null, 2), "utf8");

  return manifest;
}

/** Reads the public address manifest — no password, no decryption. */
export async function readAddressManifest(dir: string): Promise<AddressManifest> {
  const raw = await fs.readFile(path.join(dir, ADDRESS_MANIFEST_FILENAME), "utf8");
  return JSON.parse(raw) as AddressManifest;
}

/**
 * Decrypts only the operational (auth) keystore. Routine signing
 * (`withdraw`/`execute`) must never touch the fallback file — that's the
 * whole point of keeping it on the same drive but out of routine memory.
 * The returned wallet holds the private key in memory only for the one
 * signing operation the caller needs; JS/ethers objects can't be reliably
 * zeroized afterward, so "let it go" here means "stop referencing it," not
 * a guaranteed secure wipe.
 */
export async function unlockAuthKeystore(dir: string, password: string): Promise<AnyWallet> {
  const json = await fs.readFile(path.join(dir, AUTH_KEYSTORE_FILENAME), "utf8");
  return Wallet.fromEncryptedJson(json, password);
}

/** Decrypts only the fallback (recovery) keystore — see unlockAuthKeystore's note on scope. */
export async function unlockFallbackKeystore(dir: string, password: string): Promise<AnyWallet> {
  const json = await fs.readFile(path.join(dir, FALLBACK_KEYSTORE_FILENAME), "utf8");
  return Wallet.fromEncryptedJson(json, password);
}

/**
 * Copies both encrypted keystore files (and the address manifest) as-is to
 * `destDir` — a backup is a plain file copy, never a decrypt. The password
 * (kept separately, never written alongside the files) is the only real
 * secret; the file itself is meant to be freely duplicated.
 */
export async function backupKeystores(sourceDir: string, destDir: string): Promise<void> {
  await fs.mkdir(destDir, { recursive: true });
  await Promise.all(
    [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME, ADDRESS_MANIFEST_FILENAME].map((filename) =>
      fs.copyFile(path.join(sourceDir, filename), path.join(destDir, filename)),
    ),
  );
}
