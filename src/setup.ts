import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { ADDRESS_MANIFEST_FILENAME, readAddressManifest } from "./keystore.js";

export const PROVISIONING_MANIFEST_FILENAME = "vorka-manifest.json";

export interface DetectedVorkaDrive {
  path: string;
  label: string;
  configured: boolean;
  authAddress?: string;
  fallbackAddress?: string;
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
      await fs.access(path.join(candidate, PROVISIONING_MANIFEST_FILENAME));
      const realPath = await fs.realpath(candidate);
      const drive: DetectedVorkaDrive = { path: realPath, label: path.basename(realPath) || realPath, configured: false };
      try {
        await fs.access(path.join(realPath, ADDRESS_MANIFEST_FILENAME));
        const manifest = await readAddressManifest(realPath);
        drive.configured = true;
        drive.authAddress = manifest.authAddress;
        drive.fallbackAddress = manifest.fallbackAddress;
      } catch {
        // A provisioning manifest without a complete, valid signed key bundle is an unconfigured drive.
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
  return selectedRealPath;
}
