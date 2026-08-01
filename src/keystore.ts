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
import { constants as fsConstants, promises as fs } from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

export const AUTH_KEYSTORE_FILENAME = "vorka-auth.json";
export const FALLBACK_KEYSTORE_FILENAME = "vorka-fallback.json";
export const ADDRESS_MANIFEST_FILENAME = "vorka-addresses.json";
export const VORKA_DATA_DIRECTORY = ".vorka";
export const KEYSTORE_BUNDLE_FORMAT = "vorka-keystore-bundle-v1";
export const SPLIT_KEYSTORE_BUNDLE_FORMAT = "vorka-split-keystore-bundle-v2";
const execFileAsync = promisify(execFile);

function dataDir(dir: string): string { return path.join(dir, VORKA_DATA_DIRECTORY); }
function dataPath(dir: string, filename: string): string { return path.join(dataDir(dir), filename); }
export async function resolveVorkaDataFile(dir: string, filename: string): Promise<string> {
  const nested = dataPath(dir, filename);
  try {
    await fs.access(nested);
    return nested;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    return path.join(dir, filename);
  }
}

export async function protectVorkaDevice(dir: string): Promise<void> {
  if (process.platform !== "win32") return;
  try {
    const technicalDir = dataDir(dir);
    await execFileAsync("attrib", ["+H", "+S", technicalDir]);
    for (const filename of [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME, ADDRESS_MANIFEST_FILENAME]) {
      const target = dataPath(dir, filename);
      try { await fs.access(target); await execFileAsync("attrib", ["+R", target]); } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  } catch {
    // DOS attributes only prevent accidental edits; failure must never block custody or recovery.
  }
}

export async function assertSafeVorkaDataDirectory(dir: string, create = false): Promise<string> {
  const root = await fs.realpath(dir);
  const target = dataDir(root);
  if (create) await fs.mkdir(target, { recursive: true });
  const stats = await fs.lstat(target);
  if (!stats.isDirectory() || stats.isSymbolicLink()) throw new Error("Vorka data path must be a real directory on the USB");
  const resolved = await fs.realpath(target);
  const relative = path.relative(root, resolved);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new Error("Vorka data path redirects outside the USB");
  return resolved;
}

export async function allowWindowsWrite(target: string): Promise<void> {
  if (process.platform === "win32") await execFileAsync("attrib", ["-R", target]);
}

type AnyWallet = Wallet | HDNodeWallet;

interface BundlePayload {
  format: typeof KEYSTORE_BUNDLE_FORMAT | typeof SPLIT_KEYSTORE_BUNDLE_FORMAT;
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

// Length, not composition rules: NIST SP 800-63B explicitly rejects mandatory
// uppercase/symbol requirements because they push users toward predictable
// patterns ("Password1!") that cracking dictionaries target first, without
// meaningfully raising real entropy. The keystore file is deliberately
// copyable/exportable (see docs/VORKA.md), so an offline dictionary attack
// against a leaked file - not just a stolen device - is the actual threat a
// weak password fails against; scrypt's per-guess cost only multiplies the
// cost of each attempt, it doesn't help if the password is common enough to
// be found in the first few thousand guesses. 16 chars matches what a
// generated/pasted password already costs nothing to use (password managers,
// the in-app "Suggest" button) while pricing out dictionary attacks for
// anyone typing their own.
export function validatePassword(password: string, role: "auth" | "fallback"): void {
  if (Array.from(password).length < 16) {
    throw new Error(`${role} password must contain at least 16 characters`);
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
  if (value.format !== KEYSTORE_BUNDLE_FORMAT && value.format !== SPLIT_KEYSTORE_BUNDLE_FORMAT) {
    throw new Error("Unsupported keystore bundle format");
  }

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
    for (const target of [dataPath(dir, filename), path.join(dir, filename)]) {
      try {
        await fs.lstat(target);
        throw new Error(`Refusing to overwrite existing keystore bundle file: ${filename}`);
      } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
}

async function syncDirectory(dir: string): Promise<void> {
  try {
    const handle = await fs.open(dir, "r");
    try { await handle.sync(); } finally { await handle.close(); }
  } catch {
    // Some removable filesystems/Windows versions cannot fsync directories.
  }
}

async function publishExclusive(tempPath: string, finalPath: string): Promise<void> {
  try {
    await fs.lstat(finalPath);
    throw new Error(`Refusing to overwrite existing keystore bundle file: ${path.basename(finalPath)}`);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await fs.rename(tempPath, finalPath);
  await fs.chmod(finalPath, 0o600);
  await syncDirectory(path.dirname(finalPath));
}

async function publishStaged(stagePath: string, finalPath: string, generationId: string): Promise<void> {
  const expected = await fs.readFile(stagePath);
  try {
    const current = await fs.readFile(finalPath);
    if (!current.equals(expected)) throw new Error(`Conflicting existing Vorka file: ${path.basename(finalPath)}`);
    return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const publishing = path.join(path.dirname(finalPath), `.publishing-${generationId.slice(2)}-${path.basename(finalPath)}`);
  try {
    await fs.writeFile(publishing, expected, { flag: "wx", mode: 0o600 });
    const handle = await fs.open(publishing, "r+");
    try { await handle.sync(); } finally { await handle.close(); }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    const pending = await fs.readFile(publishing);
    if (!pending.equals(expected)) throw new Error(`Conflicting interrupted Vorka file: ${path.basename(finalPath)}`);
  }
  await publishExclusive(publishing, finalPath);
}

async function replaceFromStage(stagePath: string, finalPath: string, generationId: string): Promise<void> {
  const expected = await fs.readFile(stagePath);
  try {
    const current = await fs.readFile(finalPath);
    if (current.equals(expected)) return;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const publishing = path.join(path.dirname(finalPath), `.publishing-${generationId.slice(2)}-${path.basename(finalPath)}`);
  try {
    await fs.writeFile(publishing, expected, { flag: "wx", mode: 0o600 });
    const handle = await fs.open(publishing, "r+");
    try { await handle.sync(); } finally { await handle.close(); }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    if (!(await fs.readFile(publishing)).equals(expected)) {
      throw new Error(`Conflicting interrupted Vorka file: ${path.basename(finalPath)}`);
    }
  }
  try { await allowWindowsWrite(finalPath); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  await fs.rename(publishing, finalPath);
  await fs.chmod(finalPath, 0o600);
  await syncDirectory(path.dirname(finalPath));
}

async function targetAbsent(dir: string, filename: string): Promise<void> {
  for (const target of [dataPath(dir, filename), path.join(dir, filename)]) {
    try {
      await fs.lstat(target);
      throw new Error(`Refusing to overwrite existing keystore bundle file: ${filename}`);
    } catch (error: unknown) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

const SPLIT_OPERATION_PREFIX = ".operation-split-";
const REPLACEMENT_OPERATION_PREFIX = ".operation-replacement-";

async function splitOperationDirectories(dataDirectory: string): Promise<string[]> {
  const entries = await fs.readdir(dataDirectory, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isDirectory() && !entry.isSymbolicLink() && entry.name.startsWith(SPLIT_OPERATION_PREFIX))
    .map((entry) => path.join(dataDirectory, entry.name));
}

async function stagedManifest(stage: string): Promise<AddressManifest> {
  return parseManifest(await fs.readFile(path.join(stage, ADDRESS_MANIFEST_FILENAME), "utf8"));
}

async function operationDirectories(dataDirectory: string, prefix: string): Promise<string[]> {
  const entries = await fs.readdir(dataDirectory, { withFileTypes: true });
  return entries.filter((entry) => entry.isDirectory() && !entry.isSymbolicLink() && entry.name.startsWith(prefix))
    .map((entry) => path.join(dataDirectory, entry.name));
}

/** Completes a cryptographically valid interrupted two-device generation without creating new keys. */
export async function resumeInterruptedSplitGeneration(authDir: string, fallbackDir: string): Promise<AddressManifest | null> {
  const [authReal, fallbackReal] = await Promise.all([fs.realpath(authDir), fs.realpath(fallbackDir)]);
  if (authReal === fallbackReal) throw new Error("Primary and recovery keys must use two different USB drives");
  const [authDataDir, fallbackDataDir] = await Promise.all([
    assertSafeVorkaDataDirectory(authReal), assertSafeVorkaDataDirectory(fallbackReal),
  ]);
  const [authStages, fallbackStages] = await Promise.all([
    splitOperationDirectories(authDataDir), splitOperationDirectories(fallbackDataDir),
  ]);
  if (authStages.length === 0 && fallbackStages.length === 0) return null;
  if (authStages.length !== 1 || fallbackStages.length !== 1) {
    throw new Error("Interrupted Vorka setup is ambiguous; reconnect the original PRIMARY and RECOVERY keys");
  }
  const [authManifest, fallbackManifest] = await Promise.all([
    stagedManifest(authStages[0]), stagedManifest(fallbackStages[0]),
  ]);
  if (JSON.stringify(authManifest) !== JSON.stringify(fallbackManifest)) {
    throw new Error("Interrupted Vorka setup stages do not belong to the same pair");
  }
  const generationId = authManifest.generationId;
  if (!authStages[0].endsWith(`${SPLIT_OPERATION_PREFIX}${generationId.slice(2)}`) ||
      !fallbackStages[0].endsWith(`${SPLIT_OPERATION_PREFIX}${generationId.slice(2)}`)) {
    throw new Error("Interrupted Vorka setup has an invalid operation identifier");
  }
  const [authJson, fallbackJson] = await Promise.all([
    fs.readFile(path.join(authStages[0], AUTH_KEYSTORE_FILENAME), "utf8"),
    fs.readFile(path.join(fallbackStages[0], FALLBACK_KEYSTORE_FILENAME), "utf8"),
  ]);
  if (hashKeystore(authJson) !== authManifest.authKeystoreHash ||
      hashKeystore(fallbackJson) !== authManifest.fallbackKeystoreHash) {
    throw new Error("Interrupted Vorka setup contains damaged encrypted keys");
  }
  await publishStaged(path.join(authStages[0], AUTH_KEYSTORE_FILENAME), dataPath(authReal, AUTH_KEYSTORE_FILENAME), generationId);
  await publishStaged(path.join(fallbackStages[0], FALLBACK_KEYSTORE_FILENAME), dataPath(fallbackReal, FALLBACK_KEYSTORE_FILENAME), generationId);
  await publishStaged(path.join(authStages[0], ADDRESS_MANIFEST_FILENAME), dataPath(authReal, ADDRESS_MANIFEST_FILENAME), generationId);
  await publishStaged(path.join(fallbackStages[0], ADDRESS_MANIFEST_FILENAME), dataPath(fallbackReal, ADDRESS_MANIFEST_FILENAME), generationId);
  await verifySplitPair(authReal, fallbackReal);
  await Promise.all([fs.rm(authStages[0], { recursive: true }), fs.rm(fallbackStages[0], { recursive: true })]);
  await Promise.all([syncDirectory(authDataDir), syncDirectory(fallbackDataDir)]);
  await Promise.all([protectVorkaDevice(authReal), protectVorkaDevice(fallbackReal)]);
  return authManifest;
}

/** Generate operational and recovery keys onto two different devices. */
export async function generateSplitKeystores(
  authDir: string,
  fallbackDir: string,
  authPassword: string,
  fallbackPassword: string,
): Promise<AddressManifest> {
  validatePassword(authPassword, "auth");
  validatePassword(fallbackPassword, "fallback");
  const [authReal, fallbackReal] = await Promise.all([fs.realpath(authDir), fs.realpath(fallbackDir)]);
  if (authReal === fallbackReal) throw new Error("Primary and recovery keys must use two different USB drives");
  const [authDataDir, fallbackDataDir] = await Promise.all([
    assertSafeVorkaDataDirectory(authReal, true),
    assertSafeVorkaDataDirectory(fallbackReal, true),
  ]);
  const resumed = await resumeInterruptedSplitGeneration(authReal, fallbackReal);
  if (resumed) return resumed;
  await Promise.all([
    targetAbsent(authReal, AUTH_KEYSTORE_FILENAME),
    targetAbsent(authReal, FALLBACK_KEYSTORE_FILENAME),
    targetAbsent(authReal, ADDRESS_MANIFEST_FILENAME),
    targetAbsent(fallbackReal, AUTH_KEYSTORE_FILENAME),
    targetAbsent(fallbackReal, FALLBACK_KEYSTORE_FILENAME),
    targetAbsent(fallbackReal, ADDRESS_MANIFEST_FILENAME),
  ]);
  const auth = Wallet.createRandom();
  const fallback = Wallet.createRandom();
  const [authJson, fallbackJson] = await Promise.all([
    auth.encrypt(authPassword),
    fallback.encrypt(fallbackPassword),
  ]);
  const payload: BundlePayload = {
    format: SPLIT_KEYSTORE_BUNDLE_FORMAT,
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
  const manifestJson = JSON.stringify(manifest, null, 2);
  const operationName = `${SPLIT_OPERATION_PREFIX}${payload.generationId.slice(2)}`;
  const authStage = path.join(authDataDir, operationName), fallbackStage = path.join(fallbackDataDir, operationName);
  await Promise.all([fs.mkdir(authStage), fs.mkdir(fallbackStage)]);
  await Promise.all([
    writeSyncedFile(path.join(authStage, AUTH_KEYSTORE_FILENAME), authJson),
    writeSyncedFile(path.join(authStage, ADDRESS_MANIFEST_FILENAME), manifestJson),
    writeSyncedFile(path.join(fallbackStage, FALLBACK_KEYSTORE_FILENAME), fallbackJson),
    writeSyncedFile(path.join(fallbackStage, ADDRESS_MANIFEST_FILENAME), manifestJson),
  ]);
  await Promise.all([syncDirectory(authStage), syncDirectory(fallbackStage)]);
  const completed = await resumeInterruptedSplitGeneration(authReal, fallbackReal);
  if (!completed) throw new Error("Vorka setup operation disappeared before publication");
  return manifest;
}

/** Completes an interrupted Primary replacement using only signed state retained on both devices. */
export async function resumeInterruptedReplacement(newAuthDir: string, fallbackDir: string): Promise<AddressManifest | null> {
  const [newAuthReal, fallbackReal] = await Promise.all([fs.realpath(newAuthDir), fs.realpath(fallbackDir)]);
  if (newAuthReal === fallbackReal) throw new Error("The replacement primary must be a different USB drive");
  const [newAuthDataDir, fallbackDataDir] = await Promise.all([
    assertSafeVorkaDataDirectory(newAuthReal), assertSafeVorkaDataDirectory(fallbackReal),
  ]);
  const [authStages, fallbackStages] = await Promise.all([
    operationDirectories(newAuthDataDir, REPLACEMENT_OPERATION_PREFIX),
    operationDirectories(fallbackDataDir, REPLACEMENT_OPERATION_PREFIX),
  ]);
  if (authStages.length === 0 && fallbackStages.length === 0) return null;
  if (authStages.length !== 1 || fallbackStages.length !== 1) {
    throw new Error("Interrupted Primary replacement is ambiguous; reconnect the same replacement and Recovery keys");
  }
  const [authManifest, fallbackManifest] = await Promise.all([stagedManifest(authStages[0]), stagedManifest(fallbackStages[0])]);
  if (JSON.stringify(authManifest) !== JSON.stringify(fallbackManifest)) {
    throw new Error("Interrupted Primary replacement stages do not belong to the same operation");
  }
  const generationId = authManifest.generationId;
  const expectedSuffix = `${REPLACEMENT_OPERATION_PREFIX}${generationId.slice(2)}`;
  if (!authStages[0].endsWith(expectedSuffix) || !fallbackStages[0].endsWith(expectedSuffix)) {
    throw new Error("Interrupted Primary replacement has an invalid operation identifier");
  }
  const [authJson, fallbackJson] = await Promise.all([
    fs.readFile(path.join(authStages[0], AUTH_KEYSTORE_FILENAME), "utf8"),
    fs.readFile(await resolveVorkaDataFile(fallbackReal, FALLBACK_KEYSTORE_FILENAME), "utf8"),
  ]);
  if (hashKeystore(authJson) !== authManifest.authKeystoreHash || hashKeystore(fallbackJson) !== authManifest.fallbackKeystoreHash) {
    throw new Error("Interrupted Primary replacement contains damaged encrypted keys");
  }
  await publishStaged(path.join(authStages[0], AUTH_KEYSTORE_FILENAME), dataPath(newAuthReal, AUTH_KEYSTORE_FILENAME), generationId);
  await publishStaged(path.join(authStages[0], ADDRESS_MANIFEST_FILENAME), dataPath(newAuthReal, ADDRESS_MANIFEST_FILENAME), generationId);
  const recoveryManifestPath = await resolveVorkaDataFile(fallbackReal, ADDRESS_MANIFEST_FILENAME);
  await replaceFromStage(path.join(fallbackStages[0], ADDRESS_MANIFEST_FILENAME), recoveryManifestPath, generationId);
  await verifySplitPair(newAuthReal, fallbackReal);
  await Promise.all([fs.rm(authStages[0], { recursive: true }), fs.rm(fallbackStages[0], { recursive: true })]);
  await Promise.all([syncDirectory(newAuthDataDir), syncDirectory(fallbackDataDir)]);
  await Promise.all([protectVorkaDevice(newAuthReal), protectVorkaDevice(fallbackReal)]);
  return authManifest;
}

/** Replace a lost primary device while retaining the existing recovery key. */
export async function generateReplacementAuth(
  newAuthDir: string,
  fallbackDir: string,
  newAuthPassword: string,
  fallbackPassword: string,
): Promise<AddressManifest> {
  validatePassword(newAuthPassword, "auth");
  const newAuthReal = await fs.realpath(newAuthDir);
  const fallbackReal = await fs.realpath(fallbackDir);
  if (newAuthReal === fallbackReal) throw new Error("The replacement primary must be a different USB drive");
  const newAuthDataDir = await assertSafeVorkaDataDirectory(newAuthReal, true);
  const fallbackDataDir = await assertSafeVorkaDataDirectory(fallbackReal);
  const resumed = await resumeInterruptedReplacement(newAuthReal, fallbackReal);
  if (resumed) return resumed;
  const recoveryManifest = await readAddressManifest(fallbackReal);
  if (await getDeviceRole(fallbackReal) !== "recovery") throw new Error("Select the dedicated recovery Vorka key");
  const fallback = await unlockFallbackKeystore(fallbackReal, fallbackPassword);
  await Promise.all([
    targetAbsent(newAuthReal, AUTH_KEYSTORE_FILENAME), targetAbsent(newAuthReal, FALLBACK_KEYSTORE_FILENAME),
    targetAbsent(newAuthReal, ADDRESS_MANIFEST_FILENAME),
  ]);
  const auth = Wallet.createRandom();
  const [authJson, fallbackJson] = await Promise.all([
    auth.encrypt(newAuthPassword),
    fs.readFile(await resolveVorkaDataFile(fallbackReal, FALLBACK_KEYSTORE_FILENAME), "utf8"),
  ]);
  const payload: BundlePayload = {
    format: SPLIT_KEYSTORE_BUNDLE_FORMAT,
    generationId: hexlify(randomBytes(32)),
    authAddress: auth.address,
    fallbackAddress: recoveryManifest.fallbackAddress,
    authKeystoreHash: hashKeystore(authJson),
    fallbackKeystoreHash: hashKeystore(fallbackJson),
  };
  const digest = payloadDigest(payload);
  const manifest: AddressManifest = { ...payload, authSignature: await auth.signMessage(digest), fallbackSignature: await fallback.signMessage(digest) };
  const manifestJson = JSON.stringify(manifest, null, 2);
  const operationName = `${REPLACEMENT_OPERATION_PREFIX}${payload.generationId.slice(2)}`;
  const authStage = path.join(newAuthDataDir, operationName), fallbackStage = path.join(fallbackDataDir, operationName);
  await Promise.all([fs.mkdir(authStage), fs.mkdir(fallbackStage)]);
  await Promise.all([
    writeSyncedFile(path.join(authStage, AUTH_KEYSTORE_FILENAME), authJson),
    writeSyncedFile(path.join(authStage, ADDRESS_MANIFEST_FILENAME), manifestJson),
    writeSyncedFile(path.join(fallbackStage, ADDRESS_MANIFEST_FILENAME), manifestJson),
  ]);
  await Promise.all([syncDirectory(authStage), syncDirectory(fallbackStage)]);
  const completed = await resumeInterruptedReplacement(newAuthReal, fallbackReal);
  if (!completed) throw new Error("Primary replacement operation disappeared before publication");
  return manifest;
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
  const raw = await fs.readFile(await resolveVorkaDataFile(dir, ADDRESS_MANIFEST_FILENAME), "utf8");
  return parseManifest(raw);
}

export async function verifyRoleFile(dir: string, role: "auth" | "fallback"): Promise<{ manifest: AddressManifest; json: string }> {
  const manifest = await readManifestOnly(dir);
  const filename = role === "auth" ? AUTH_KEYSTORE_FILENAME : FALLBACK_KEYSTORE_FILENAME;
  const expectedHash = role === "auth" ? manifest.authKeystoreHash : manifest.fallbackKeystoreHash;
  const json = await fs.readFile(await resolveVorkaDataFile(dir, filename), "utf8");
  if (hashKeystore(json) !== expectedHash) throw new Error(`${role} keystore does not match signed bundle`);
  return { manifest, json };
}

export async function getDeviceRole(dir: string): Promise<"primary" | "recovery" | "legacy"> {
  const present = async (filename: string): Promise<boolean> => {
    const target = await resolveVorkaDataFile(dir, filename);
    try { await fs.access(target); return true; } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  };
  const [authPresent, fallbackPresent] = await Promise.all([
    present(AUTH_KEYSTORE_FILENAME),
    present(FALLBACK_KEYSTORE_FILENAME),
  ]);
  if (authPresent && fallbackPresent) return "legacy";
  if (authPresent) return "primary";
  if (fallbackPresent) return "recovery";
  throw new Error("No Vorka keystore exists on this device");
}

/** Verifies the signed manifest and every role file present on this device. */
export async function readAddressManifest(dir: string): Promise<AddressManifest> {
  const manifest = await readManifestOnly(dir);
  const role = await getDeviceRole(dir);
  if (manifest.format === KEYSTORE_BUNDLE_FORMAT && role !== "legacy") {
    throw new Error("Legacy keystore bundle is incomplete");
  }
  if (role === "primary") await verifyRoleFile(dir, "auth");
  else if (role === "recovery") await verifyRoleFile(dir, "fallback");
  else {
    const [auth, fallback] = await Promise.all([verifyRoleFile(dir, "auth"), verifyRoleFile(dir, "fallback")]);
    if (auth.manifest.generationId !== fallback.manifest.generationId) throw new Error("Keystore bundle mismatch");
  }
  return manifest;
}

/** Re-reads and verifies both physical devices before setup or replacement is declared complete. */
export async function verifySplitPair(authDir: string, fallbackDir: string): Promise<AddressManifest> {
  const [authReal, fallbackReal] = await Promise.all([fs.realpath(authDir), fs.realpath(fallbackDir)]);
  if (authReal === fallbackReal) throw new Error("Primary and Recovery must be different physical paths");
  const [authRole, fallbackRole, authManifest, fallbackManifest] = await Promise.all([
    getDeviceRole(authReal),
    getDeviceRole(fallbackReal),
    readAddressManifest(authReal),
    readAddressManifest(fallbackReal),
  ]);
  if (authRole !== "primary" || fallbackRole !== "recovery") {
    throw new Error("Vorka pair roles are invalid or reversed");
  }
  const authBundle = JSON.stringify(authManifest);
  const fallbackBundle = JSON.stringify(fallbackManifest);
  if (authBundle !== fallbackBundle) throw new Error("Primary and Recovery do not belong to the same Vorka pair");
  return authManifest;
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
  const role = await getDeviceRole(sourceDir);
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
    const roleFiles = role === "primary" ? [AUTH_KEYSTORE_FILENAME]
      : role === "recovery" ? [FALLBACK_KEYSTORE_FILENAME]
      : [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME];
    for (const filename of [...roleFiles, ADDRESS_MANIFEST_FILENAME]) {
      await fs.copyFile(await resolveVorkaDataFile(sourceDir, filename), path.join(stageDir, filename), fsConstants.COPYFILE_EXCL);
      await fs.chmod(path.join(stageDir, filename), 0o600);
    }
    await readAddressManifest(stageDir);
    await fs.rename(stageDir, destDir);
  } catch (error) {
    await fs.rm(stageDir, { recursive: true, force: true });
    throw error;
  }
}

/** Restores a verified ciphertext-only backup onto an empty prepared device without decrypting it. */
export async function restoreKeystoreBackup(
  backupDir: string,
  destinationDeviceDir: string,
  expectedRole?: "primary" | "recovery",
): Promise<AddressManifest> {
  const [backupReal, destinationReal] = await Promise.all([fs.realpath(backupDir), fs.realpath(destinationDeviceDir)]);
  if (backupReal === destinationReal) throw new Error("Backup source and restore destination must be different paths");
  const role = await getDeviceRole(backupReal);
  if (role === "legacy") throw new Error("Legacy combined backups cannot be restored onto a split Vorka device");
  if (expectedRole && role !== expectedRole) throw new Error(`This is a ${role} backup, not a ${expectedRole} backup`);
  const manifest = await readAddressManifest(backupReal);
  const destinationDataDir = await assertSafeVorkaDataDirectory(destinationReal, true);
  const operationName = `.operation-restore-${manifest.generationId.slice(2)}`;
  const stage = path.join(destinationDataDir, operationName);
  const roleFilename = role === "primary" ? AUTH_KEYSTORE_FILENAME : FALLBACK_KEYSTORE_FILENAME;
  let resume = false;
  try { resume = (await fs.lstat(stage)).isDirectory(); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  if (resume) {
    const staged = await readAddressManifest(stage);
    if (JSON.stringify(staged) !== JSON.stringify(manifest) || await getDeviceRole(stage) !== role) {
      throw new Error("Interrupted restore stage does not match the selected backup");
    }
  } else {
    await Promise.all([
      targetAbsent(destinationReal, AUTH_KEYSTORE_FILENAME),
      targetAbsent(destinationReal, FALLBACK_KEYSTORE_FILENAME),
      targetAbsent(destinationReal, ADDRESS_MANIFEST_FILENAME),
    ]);
    await fs.mkdir(stage);
    await Promise.all([
      writeSyncedFile(path.join(stage, roleFilename), await fs.readFile(await resolveVorkaDataFile(backupReal, roleFilename), "utf8")),
      writeSyncedFile(path.join(stage, ADDRESS_MANIFEST_FILENAME), await fs.readFile(await resolveVorkaDataFile(backupReal, ADDRESS_MANIFEST_FILENAME), "utf8")),
    ]);
    await syncDirectory(stage);
  }
  try {
    await publishStaged(path.join(stage, roleFilename), dataPath(destinationReal, roleFilename), manifest.generationId);
    await publishStaged(path.join(stage, ADDRESS_MANIFEST_FILENAME), dataPath(destinationReal, ADDRESS_MANIFEST_FILENAME), manifest.generationId);
    const restored = await readAddressManifest(destinationReal);
    if (JSON.stringify(restored) !== JSON.stringify(manifest)) throw new Error("Restored Vorka backup does not match its source manifest");
    await fs.rm(stage, { recursive: true });
    await syncDirectory(destinationDataDir);
    await protectVorkaDevice(destinationReal);
    return restored;
  } catch (error) {
    // Keep a complete stage for diagnosis/resume; never claim success on a partial restore.
    throw error;
  }
}
