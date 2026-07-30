import { execFileSync } from "node:child_process";
import { copyFile, mkdir, rm } from "node:fs/promises";
import path from "node:path";
import process from "node:process";

const root = process.cwd();
const output = path.join(root, ".native-build");
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
const esbuild = path.join(root, "node_modules", ".bin", process.platform === "win32" ? "esbuild.cmd" : "esbuild");
const common = ["--bundle", "--platform=node", "--format=cjs", "--external:electron"];
execFileSync(esbuild, ["src/native-main.ts", ...common, `--outfile=${path.join(output, "native-main.cjs")}`], { stdio: "inherit", shell: process.platform === "win32" });
execFileSync(esbuild, ["src/native-preload.ts", ...common, `--outfile=${path.join(output, "native-preload.cjs")}`], { stdio: "inherit", shell: process.platform === "win32" });
execFileSync(esbuild, ["src/native-renderer.ts", "--bundle", "--platform=browser", "--format=iife", `--outfile=${path.join(output, "native-renderer.js")}`], { stdio: "inherit", shell: process.platform === "win32" });
await copyFile(path.join(root, "src", "native-ui.html"), path.join(output, "native-ui.html"));
await copyFile(path.join(root, "src", "native-ui.css"), path.join(output, "native-ui.css"));
if (process.argv.includes("--package")) {
  const builder = path.join(root, "node_modules", ".bin", process.platform === "win32" ? "electron-builder.cmd" : "electron-builder");
  execFileSync(builder, ["--win", "portable", "--x64"], { stdio: "inherit", shell: process.platform === "win32" });
}
