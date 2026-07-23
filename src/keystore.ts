import {
  Wallet,
  getAddress,
  getBytes,
  hexlify,
  keccak256,
  randomBytes,
  toUtf8Bytes,
  verifyMessage,
  type HDNodeWallet,
} from "ethers";
import { ZxcvbnFactory } from "@zxcvbn-ts/core";
import { adjacencyGraphs, dictionary } from "@zxcvbn-ts/language-common";
import { constants as fsConstants, promises as fs } from "node:fs";
import path from "node:path";

export const AUTH_KEYSTORE_FILENAME = "vorka-auth.json";
export const FALLBACK_KEYSTORE_FILENAME = "vorka-fallback.json";
export const ADDRESS_MANIFEST_FILENAME = "vorka-addresses.json";
export const KEYSTORE_BUNDLE_FORMAT = "vorka-keystore-bundle-v1";
const passwordEstimator = new ZxcvbnFactory({ dictionary, graphs: adjacencyGraphs });

type AnyWallet = Wallet | HDNodeWallet;

interface BundlePayload {
  format: typeof KEYSTORE_BUNDLE_FORMAT;
  generationId: string;
  authAddress: string;
  fallbackAddress: string;
  authKeystoreHash: string;
  fallbackKeystoreHash: string;
}

export interface AddressManifest extends BundlePayload {
  authSignature: string;
  fallbackSignature: string;
}

function canonicalPayload(payload: BundlePayload): string {
  return JSON.stringify({
    format: payload.format,
    generationId: payload.generationId,
    authAddress: payload.authAddress,
    fallbackAddress: payload.fallbackAddress,
    authKeystoreHash: payload.authKeystoreHash,
    fallbackKeystoreHash: payload.fallbackKeystoreHash,
  });
}

function payloadDigest(payload: BundlePayload): Uint8Array {
  return getBytes(keccak256(toUtf8Bytes(canonicalPayload(payload))));
}

function hashKeystore(json: string): string {
  return keccak256(toUtf8Bytes(json));
}

export function validatePassword(password: string, role: "auth" | "fallback"): void {
  if (Array.from(password).length < 16) {
    throw new Error(`${role} password must contain at least 16 characters`);
  }
  if (passwordEstimator.check(password).score < 3) {
    throw new Error(`${role} password is too easy to guess`);
  }
}

function parseManifest(raw: string): AddressManifest {
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object") throw new Error("Invalid keystore bundle manifest");
  const value = parsed as Record<string, unknown>;
  const stringFields = [
    "format",
    "generationId",
    "authAddress",
    "fallbackAddress",
    "authKeystoreHash",
    "fallbackKeystoreHash",
    "authSignature",
    "fallbackSignature",
  ];
  for (const field of stringFields) {
    if (typeof value[field] !== "string") throw new Error(`Invalid keystore bundle field: ${field}`);
  }
  if (value.format !== KEYSTORE_BUNDLE_FORMAT) throw new Error("Unsupported keystore bundle format");

  const manifest = value as unknown as AddressManifest;
  const normalized: AddressManifest = {
    ...manifest,
    authAddress: getAddress(manifest.authAddress),
    fallbackAddress: getAddress(manifest.fallbackAddress),
  };
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized.generationId)) throw new Error("Invalid generation ID");
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized.authKeystoreHash)) throw new Error("Invalid auth keystore hash");
  if (!/^0x[0-9a-fA-F]{64}$/.test(normalized.fallbackKeystoreHash)) {
    throw new Error("Invalid fallback keystore hash");
  }

  const digest = payloadDigest(normalized);
  if (getAddress(verifyMessage(digest, normalized.authSignature)) !== normalized.authAddress) {
    throw new Error("Invalid auth bundle signature");
  }
  if (getAddress(verifyMessage(digest, normalized.fallbackSignature)) !== normalized.fallbackAddress) {
    throw new Error("Invalid fallback bundle signature");
  }
  return normalized;
}

async function writeSyncedFile(filePath: string, contents: string): Promise<void> {
  const handle = await fs.open(filePath, "wx", 0o600);
  try {
    await handle.writeFile(contents, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function assertTargetsAbsent(dir: string): Promise<void> {
  for (const filename of [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME, ADDRESS_MANIFEST_FILENAME]) {
    try {
      await fs.lstat(path.join(dir, filename));
      throw new Error(`Refusing to overwrite existing keystore bundle file: ${filename}`);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

async function publishExclusive(tempPath: string, finalPath: string): Promise<void> {
  await fs.copyFile(tempPath, finalPath, fsConstants.COPYFILE_EXCL);
  await fs.chmod(finalPath, 0o600);
}

/** Generates a signed, versioned bundle and never overwrites existing key material. */
export async function generateKeystores(
  dir: string,
  authPassword: string,
  fallbackPassword: string,
): Promise<AddressManifest> {
  validatePassword(authPassword, "auth");
  validatePassword(fallbackPassword, "fallback");
  if (authPassword === fallbackPassword) throw new Error("Auth and fallback passwords must differ");

  await fs.mkdir(dir, { recursive: true });
  await assertTargetsAbsent(dir);

  const auth = Wallet.createRandom();
  const fallback = Wallet.createRandom();
  const [authJson, fallbackJson] = await Promise.all([
    auth.encrypt(authPassword),
    fallback.encrypt(fallbackPassword),
  ]);
  const payload: BundlePayload = {
    format: KEYSTORE_BUNDLE_FORMAT,
    generationId: hexlify(randomBytes(32)),
    authAddress: auth.address,
    fallbackAddress: fallback.address,
    authKeystoreHash: hashKeystore(authJson),
    fallbackKeystoreHash: hashKeystore(fallbackJson),
  };
  const digest = payloadDigest(payload);
  const manifest: AddressManifest = {
    ...payload,
    authSignature: await auth.signMessage(digest),
    fallbackSignature: await fallback.signMessage(digest),
  };

  const tempDir = await fs.mkdtemp(path.join(dir, ".vorka-generate-"));
  try {
    const authTemp = path.join(tempDir, AUTH_KEYSTORE_FILENAME);
    const fallbackTemp = path.join(tempDir, FALLBACK_KEYSTORE_FILENAME);
    const manifestTemp = path.join(tempDir, ADDRESS_MANIFEST_FILENAME);
    await Promise.all([
      writeSyncedFile(authTemp, authJson),
      writeSyncedFile(fallbackTemp, fallbackJson),
      writeSyncedFile(manifestTemp, JSON.stringify(manifest, null, 2)),
    ]);
    await assertTargetsAbsent(dir);
    await publishExclusive(authTemp, path.join(dir, AUTH_KEYSTORE_FILENAME));
    await publishExclusive(fallbackTemp, path.join(dir, FALLBACK_KEYSTORE_FILENAME));
    // Manifest is the commit marker and is deliberately published last.
    await publishExclusive(manifestTemp, path.join(dir, ADDRESS_MANIFEST_FILENAME));
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true });
  }
  return manifest;
}

async function readManifestOnly(dir: string): Promise<AddressManifest> {
  const raw = await fs.readFile(path.join(dir, ADDRESS_MANIFEST_FILENAME), "utf8");
  return parseManifest(raw);
}

async function verifyRoleFile(dir: string, role: "auth" | "fallback"): Promise<{ manifest: AddressManifest; json: string }> {
  const manifest = await readManifestOnly(dir);
  const filename = role === "auth" ? AUTH_KEYSTORE_FILENAME : FALLBACK_KEYSTORE_FILENAME;
  const expectedHash = role === "auth" ? manifest.authKeystoreHash : manifest.fallbackKeystoreHash;
  const json = await fs.readFile(path.join(dir, filename), "utf8");
  if (hashKeystore(json) !== expectedHash) throw new Error(`${role} keystore does not match signed bundle`);
  return { manifest, json };
}

/** Verifies both encrypted files and signatures without decrypting either key. */
export async function readAddressManifest(dir: string): Promise<AddressManifest> {
  const [auth, fallback] = await Promise.all([verifyRoleFile(dir, "auth"), verifyRoleFile(dir, "fallback")]);
  if (auth.manifest.generationId !== fallback.manifest.generationId) throw new Error("Keystore bundle mismatch");
  return auth.manifest;
}

export async function unlockAuthKeystore(dir: string, password: string): Promise<AnyWallet> {
  const { manifest, json } = await verifyRoleFile(dir, "auth");
  const wallet = await Wallet.fromEncryptedJson(json, password);
  if (wallet.address !== manifest.authAddress) throw new Error("Auth keystore address does not match signed bundle");
  return wallet;
}

export async function unlockFallbackKeystore(dir: string, password: string): Promise<AnyWallet> {
  const { manifest, json } = await verifyRoleFile(dir, "fallback");
  const wallet = await Wallet.fromEncryptedJson(json, password);
  if (wallet.address !== manifest.fallbackAddress) throw new Error("Fallback keystore address does not match signed bundle");
  return wallet;
}

/** Creates a verified backup at a new destination without overwriting existing data. */
export async function backupKeystores(sourceDir: string, destDir: string): Promise<void> {
  await readAddressManifest(sourceDir);
  const parent = path.dirname(destDir);
  await fs.mkdir(parent, { recursive: true });
  try {
    await fs.lstat(destDir);
    throw new Error(`Refusing to overwrite existing backup destination: ${destDir}`);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }

  const stageDir = await fs.mkdtemp(path.join(parent, ".vorka-backup-"));
  try {
    for (const filename of [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME, ADDRESS_MANIFEST_FILENAME]) {
      await fs.copyFile(path.join(sourceDir, filename), path.join(stageDir, filename), fsConstants.COPYFILE_EXCL);
      await fs.chmod(path.join(stageDir, filename), 0o600);
    }
    await readAddressManifest(stageDir);
    await fs.rename(stageDir, destDir);
  } catch (error) {
    await fs.rm(stageDir, { recursive: true, force: true });
    throw error;
  }
}
