import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  ADDRESS_MANIFEST_FILENAME,
  AUTH_KEYSTORE_FILENAME,
  FALLBACK_KEYSTORE_FILENAME,
  readAddressManifest,
} from "./keystore.js";

export const PROVISIONING_MANIFEST_FILENAME = "vorka-manifest.json";

export interface DetectedVorkaDrive {
  path: string;
  label: string;
  configured: boolean;
  damaged: boolean;
  problem?: string;
  authAddress?: string;
  fallbackAddress?: string;
}

const MINIMUM_FREE_BYTES = 5 * 1024 * 1024;

async function pathExists(target: string): Promise<boolean> {
  return fs.access(target).then(() => true).catch(() => false);
}

async function validateProvisioningManifest(dir: string): Promise<void> {
  let value: unknown;
  try {
    value = JSON.parse(await fs.readFile(path.join(dir, PROVISIONING_MANIFEST_FILENAME), "utf8"));
  } catch {
    throw new Error("The Vorka provisioning marker is unreadable or invalid");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The Vorka provisioning marker is invalid");
  }
  const manifest = value as Record<string, unknown>;
  if (manifest.format !== "vorka-provisioned-drive-v1" ||
      typeof manifest.provisionedAt !== "string" || Number.isNaN(Date.parse(manifest.provisionedAt)) ||
      typeof manifest.appVersion !== "string" ||
      !Array.isArray(manifest.portableApps) ||
      !manifest.portableApps.every((entry) => typeof entry === "string")) {
    throw new Error("The Vorka provisioning marker has an unsupported format");
  }
}

export async function assertDriveWritableAndSpacious(dir: string): Promise<void> {
  let probeDir: string | undefined;
  try {
    const stats = await fs.statfs(dir);
    if (stats.bavail * stats.bsize < MINIMUM_FREE_BYTES) {
      throw new Error("The Vorka drive does not have enough free space");
    }
    probeDir = await fs.mkdtemp(path.join(dir, ".vorka-write-test-"));
  } catch (error) {
    if (error instanceof Error && /enough free space/.test(error.message)) throw error;
    throw new Error("The Vorka drive is not writable; check write protection and reconnect it");
  } finally {
    if (probeDir) await fs.rm(probeDir, { recursive: true, force: true });
  }
}

export function defaultDriveRoots(platform = process.platform, home = os.homedir()): string[] {
  if (platform === "win32") return Array.from({ length: 23 }, (_, index) => `${String.fromCharCode(68 + index)}:\\`);
  if (platform === "darwin") return ["/Volumes"];
  const user = path.basename(home);
  return [`/run/media/${user}`, `/media/${user}`];
}

async function directoryChildren(root: string, platform = process.platform): Promise<string[]> {
  if (platform === "win32") return [root];
  try {
    return (await fs.readdir(root, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => path.join(root, entry.name));
  } catch {
    return [];
  }
}

export async function detectVorkaDrives(
  roots = defaultDriveRoots(),
  platform = process.platform,
): Promise<DetectedVorkaDrive[]> {
  const candidates = (await Promise.all(roots.map((root) => directoryChildren(root, platform)))).flat();
  const drives: DetectedVorkaDrive[] = [];
  for (const candidate of candidates) {
    try {
      await validateProvisioningManifest(candidate);
      const realPath = await fs.realpath(candidate);
      const drive: DetectedVorkaDrive = {
        path: realPath,
        label: path.basename(realPath) || realPath,
        configured: false,
        damaged: false,
      };
      const bundleFiles = [AUTH_KEYSTORE_FILENAME, FALLBACK_KEYSTORE_FILENAME, ADDRESS_MANIFEST_FILENAME];
      const bundlePresence = await Promise.all(bundleFiles.map((filename) => pathExists(path.join(realPath, filename))));
      if (bundlePresence.some(Boolean)) {
        try {
          const manifest = await readAddressManifest(realPath);
          drive.configured = true;
          drive.authAddress = manifest.authAddress;
          drive.fallbackAddress = manifest.fallbackAddress;
        } catch {
          drive.damaged = true;
          drive.problem = "The encrypted key bundle is incomplete or damaged; setup will not overwrite it";
        }
      }
      drives.push(drive);
    } catch {
      // Missing/inaccessible roots and ordinary removable drives are intentionally ignored.
    }
  }
  return drives.sort((a, b) => a.path.localeCompare(b.path));
}

export async function requireDetectedUnconfiguredDrive(
  selectedPath: string,
  roots = defaultDriveRoots(),
  platform = process.platform,
): Promise<string> {
  const selectedRealPath = await fs.realpath(selectedPath);
  const detected = await detectVorkaDrives(roots, platform);
  const match = detected.find((drive) => drive.path === selectedRealPath);
  if (!match) throw new Error("Selected path is not a detected provisioned Vorka drive");
  if (match.configured) throw new Error("This Vorka drive is already configured; refusing to replace its keys");
  if (match.damaged) throw new Error(match.problem ?? "This Vorka drive contains a damaged key bundle");
  await assertDriveWritableAndSpacious(selectedRealPath);
  return selectedRealPath;
}
