import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const releaseDir = path.join(root, "release");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const names = (await readdir(releaseDir)).filter((name) => /^Vorka-Windows-.+\.exe$/.test(name));
if (names.length !== 1) throw new Error(`Expected exactly one Windows release executable, found ${names.length}`);
const sourceRevision = process.env.GITHUB_SHA || execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const executable = await readFile(path.join(releaseDir, names[0]));
const manifest = {
  format: "vorka-release-manifest-v1",
  version: packageJson.version,
  sourceRevision,
  generatedAt: new Date().toISOString(),
  files: [{ name: names[0], size: executable.length, sha256: createHash("sha256").update(executable).digest("hex") }],
};
await writeFile(path.join(releaseDir, "vorka-release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, { flag: "wx" });
