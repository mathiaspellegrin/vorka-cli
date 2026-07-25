import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const buildDir = path.join(root, ".portable-build");
const releaseDir = path.join(root, "release");
const executableName = `vorka-${process.platform}-${process.arch}${process.platform === "win32" ? ".exe" : ""}`;
const executablePath = path.join(releaseDir, executableName);
const bundlePath = path.join(buildDir, "cli.cjs");
const blobPath = path.join(buildDir, "sea-prep.blob");
const configPath = path.join(buildDir, "sea-config.json");
const seaFuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

await rm(buildDir, { recursive: true, force: true });
await mkdir(buildDir, { recursive: true });
await mkdir(releaseDir, { recursive: true });

execFileSync(
  path.join(root, "node_modules", ".bin", process.platform === "win32" ? "esbuild.cmd" : "esbuild"),
  ["src/cli.ts", "--bundle", "--platform=node", "--format=cjs", `--outfile=${bundlePath}`],
  { stdio: "inherit" },
);

await writeFile(
  configPath,
  JSON.stringify(
    {
      main: bundlePath,
      output: blobPath,
      disableExperimentalSEAWarning: true,
      useSnapshot: false,
      useCodeCache: false,
    },
    null,
    2,
  ),
);
execFileSync(process.execPath, ["--experimental-sea-config", configPath], { stdio: "inherit" });
const nodeBinary = await readFile(process.execPath);
if (!nodeBinary.includes(Buffer.from(seaFuse))) {
  throw new Error(
    `Node binary ${process.execPath} cannot host a SEA (the SEA fuse is absent). ` +
      "Build with an official statically linked Node distribution on the target OS.",
  );
}
await copyFile(process.execPath, executablePath);

if (process.platform === "darwin") {
  execFileSync("codesign", ["--remove-signature", executablePath], { stdio: "inherit" });
}
execFileSync(
  path.join(root, "node_modules", ".bin", process.platform === "win32" ? "postject.cmd" : "postject"),
  [
    executablePath,
    "NODE_SEA_BLOB",
    blobPath,
    "--sentinel-fuse",
    seaFuse,
  ],
  { stdio: "inherit" },
);
if (process.platform === "darwin") {
  execFileSync("codesign", ["--sign", "-", executablePath], { stdio: "inherit" });
}

console.log(`Portable CLI built: ${executablePath}`);
