import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PROVISIONING_MANIFEST_FILENAME,
  defaultDriveRoots,
  detectVorkaDrives,
  requireDetectedUnconfiguredDrive,
} from "../src/setup.js";

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
    await fs.writeFile(path.join(vorka, PROVISIONING_MANIFEST_FILENAME), "{}");

    const drives = await detectVorkaDrives([root], "linux");
    expect(drives).toHaveLength(1);
    expect(drives[0]).toMatchObject({ path: await fs.realpath(vorka), configured: false });
  });

  it("authorizes only an auto-detected provisioned drive", async () => {
    const root = await tempDir();
    const vorka = path.join(root, "VORKA");
    const ordinary = path.join(root, "ORDINARY");
    await fs.mkdir(vorka);
    await fs.mkdir(ordinary);
    await fs.writeFile(path.join(vorka, PROVISIONING_MANIFEST_FILENAME), "{}");

    await expect(requireDetectedUnconfiguredDrive(vorka, [root], "linux")).resolves.toBe(await fs.realpath(vorka));
    await expect(requireDetectedUnconfiguredDrive(ordinary, [root], "linux")).rejects.toThrow(/not a detected/i);
  });
});
