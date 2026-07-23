import { Wallet, type HDNodeWallet } from "ethers";
import { promises as fs } from "node:fs";
import path from "node:path";

export const AUTH_KEYSTORE_FILENAME = "vorka-auth.json";
export const FALLBACK_KEYSTORE_FILENAME = "vorka-fallback.json";

type AnyWallet = Wallet | HDNodeWallet;

export interface UnlockedKeys {
  auth: AnyWallet;
  fallback: AnyWallet;
}

/**
 * Generates fresh auth/fallback keypairs and writes both as standard Ethereum
 * V3 keystores (scrypt + AES, via ethers' own encryption) to `dir`, both
 * protected by the same `password` — one password, two keystore files, one
 * drive. Nothing unencrypted ever touches disk.
 */
export async function generateKeystores(
  dir: string,
  password: string,
): Promise<{ authAddress: string; fallbackAddress: string }> {
  const auth = Wallet.createRandom();
  const fallback = Wallet.createRandom();

  const authJson = await auth.encrypt(password);
  const fallbackJson = await fallback.encrypt(password);

  await fs.mkdir(dir, { recursive: true });
  await fs.writeFile(path.join(dir, AUTH_KEYSTORE_FILENAME), authJson, "utf8");
  await fs.writeFile(path.join(dir, FALLBACK_KEYSTORE_FILENAME), fallbackJson, "utf8");

  return { authAddress: auth.address, fallbackAddress: fallback.address };
}

/**
 * Decrypts both keystores in `dir` with `password`. Returns Wallet instances
 * holding the private key only in memory — callers must use them for exactly
 * the one signing operation needed and then let them go, never cache across
 * commands or sessions.
 */
export async function unlockKeystores(dir: string, password: string): Promise<UnlockedKeys> {
  const [authJson, fallbackJson] = await Promise.all([
    fs.readFile(path.join(dir, AUTH_KEYSTORE_FILENAME), "utf8"),
    fs.readFile(path.join(dir, FALLBACK_KEYSTORE_FILENAME), "utf8"),
  ]);

  const [auth, fallback] = await Promise.all([
    Wallet.fromEncryptedJson(authJson, password),
    Wallet.fromEncryptedJson(fallbackJson, password),
  ]);

  return { auth, fallback };
}

/**
 * Copies both encrypted keystore files as-is to `destDir` — a backup is a
 * plain file copy, never a decrypt. The password (kept separately, never
 * written alongside the files) is the only real secret; the file itself is
 * meant to be freely duplicated.
 */
export async function backupKeystores(sourceDir: string, destDir: string): Promise<void> {
  await fs.mkdir(destDir, { recursive: true });
  await Promise.all(
    [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME].map((filename) =>
      fs.copyFile(path.join(sourceDir, filename), path.join(destDir, filename)),
    ),
  );
}
