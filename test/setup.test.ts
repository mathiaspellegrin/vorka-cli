import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PROVISIONING_MANIFEST_FILENAME,
  assertDriveWritableAndSpacious,
  defaultDriveRoots,
  detectVorkaDrives,
  requireDetectedUnconfiguredDrive,
} from "../src/setup.js";
import { VORKA_DATA_DIRECTORY } from "../src/keystore.js";

const provisioningManifest = JSON.stringify({
  format: "vorka-provisioned-drive-v1",
  role: "primary",
  provisionedAt: "2026-07-30T00:00:00.000Z",
  appVersion: "0.1.0",
  portableApps: ["1 - WINDOWS/START VORKA.exe"],
});

const temporaryDirectories: string[] = [];

async function tempDir(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "vorka-setup-test-"));
  temporaryDirectories.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe("setup drive detection", () => {
  it("uses removable-volume roots for each desktop platform", () => {
    expect(defaultDriveRoots("linux", "/home/alice")).toEqual(["/run/media/alice", "/media/alice"]);
    expect(defaultDriveRoots("darwin", "/Users/alice")).toEqual(["/Volumes"]);
    expect(defaultDriveRoots("win32", "C:\\Users\\alice")).toContain("D:\\");
  });

  it("detects only provisioned Vorka drives", async () => {
    const root = await tempDir();
    const vorka = path.join(root, "VORKA");
    const ordinary = path.join(root, "ORDINARY");
    await fs.mkdir(vorka);
    await fs.mkdir(ordinary);
    await fs.mkdir(path.join(vorka, VORKA_DATA_DIRECTORY));
    await fs.writeFile(path.join(vorka, VORKA_DATA_DIRECTORY, PROVISIONING_MANIFEST_FILENAME), provisioningManifest);

    const drives = await detectVorkaDrives([root], "linux");
    expect(drives).toHaveLength(1);
    expect(drives[0]).toMatchObject({ path: await fs.realpath(vorka), configured: false, damaged: false, provisionedRole: "primary" });
  });

  it("authorizes only an auto-detected provisioned drive", async () => {
    const root = await tempDir();
    const vorka = path.join(root, "VORKA");
    const ordinary = path.join(root, "ORDINARY");
    await fs.mkdir(vorka);
    await fs.mkdir(ordinary);
    await fs.writeFile(path.join(vorka, PROVISIONING_MANIFEST_FILENAME), provisioningManifest);

    await expect(requireDetectedUnconfiguredDrive(vorka, [root], "linux")).resolves.toBe(await fs.realpath(vorka));
    await expect(requireDetectedUnconfiguredDrive(vorka, [root], "linux", "primary")).resolves.toBe(await fs.realpath(vorka));
    await expect(requireDetectedUnconfiguredDrive(vorka, [root], "linux", "recovery")).rejects.toThrow(/not provisioned as the recovery/i);
    await expect(requireDetectedUnconfiguredDrive(ordinary, [root], "linux")).rejects.toThrow(/not a detected/i);
  });

  it("rejects malformed provisioning markers", async () => {
    const root = await tempDir();
    const vorka = path.join(root, "VORKA");
    await fs.mkdir(vorka);
    await fs.writeFile(path.join(vorka, PROVISIONING_MANIFEST_FILENAME), "{}");

    await expect(detectVorkaDrives([root], "linux")).resolves.toEqual([]);
  });

  it("reports a partial key bundle as damaged and refuses to overwrite it", async () => {
    const root = await tempDir();
    const vorka = path.join(root, "VORKA");
    await fs.mkdir(vorka);
    await fs.writeFile(path.join(vorka, PROVISIONING_MANIFEST_FILENAME), provisioningManifest);
    await fs.writeFile(path.join(vorka, "vorka-auth.json"), "partial");

    const drives = await detectVorkaDrives([root], "linux");
    expect(drives[0]).toMatchObject({ configured: false, damaged: true });
    await expect(requireDetectedUnconfiguredDrive(vorka, [root], "linux")).rejects.toThrow(/incomplete or damaged/i);
  });

  it("preflights free space and write access", async () => {
    const dir = await tempDir();
    await expect(assertDriveWritableAndSpacious(dir)).resolves.toBeUndefined();
    await expect(assertDriveWritableAndSpacious(path.join(dir, "missing"))).rejects.toThrow(/not writable/i);
  });
});
