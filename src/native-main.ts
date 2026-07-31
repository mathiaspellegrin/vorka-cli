import { app, BrowserWindow, ipcMain } from "electron";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { ZeroAddress, formatEther, getAddress, parseEther } from "ethers";
import { generateReplacementAuth, generateSplitKeystores, protectVorkaDevice, readAddressManifest, unlockAuthKeystore, unlockFallbackKeystore } from "./keystore.js";
import { detectVorkaDrives, requireDetectedUnconfiguredDrive } from "./setup.js";
import {
  createVault,
  getValidatedProvider,
  getVaultState,
  signingDeadline,
  submitWithdraw,
  submitFreeze,
  submitModifyIdentity,
  type ChainConfig,
} from "./chain.js";
import { signFreeze, signModifyIdentity, signWithdraw } from "./sign.js";

let generating = false;

function createWindow(): void {
  const window = new BrowserWindow({
    width: 820,
    height: 780,
    minWidth: 620,
    minHeight: 640,
    show: true,
    title: "Vorka",
    icon: path.join(__dirname, "vorka.ico"),
    backgroundColor: "#e7e2d6",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "native-preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
    },
  });
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => event.preventDefault());
  void window.loadFile(path.join(__dirname, "native-ui.html"));
}

function objectBody(body: unknown): Record<string, unknown> {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid request");
  return body as Record<string, unknown>;
}

function stringField(value: Record<string, unknown>, name: string): string {
  if (typeof value[name] !== "string" || value[name].length === 0) throw new Error(`Missing field: ${name}`);
  return value[name];
}

function chainFrom(value: Record<string, unknown>): ChainConfig {
  const rpc = stringField(value, "rpc");
  const chainId = value.chainId;
  if (!Number.isSafeInteger(chainId) || Number(chainId) <= 0) throw new Error("Chain ID must be a positive integer");
  return { rpc, chainId: Number(chainId) };
}

ipcMain.handle("vorka:list-drives", async () => {
  const drives = await detectVorkaDrives();
  await Promise.all(drives.map((drive) => protectVorkaDevice(drive.path)));
  return drives;
});
ipcMain.handle("vorka:generate-password", () => randomBytes(24).toString("base64url"));
ipcMain.handle("vorka:generate", async (_event, body: unknown) => {
  if (generating) throw new Error("Key generation is already running");
  const value = objectBody(body);
  if (typeof value.primaryPath !== "string" || typeof value.recoveryPath !== "string" ||
      typeof value.authPassword !== "string" ||
      typeof value.fallbackPassword !== "string") {
    throw new Error("Missing setup fields");
  }
  generating = true;
  try {
    const [primaryPath, recoveryPath] = await Promise.all([
      requireDetectedUnconfiguredDrive(value.primaryPath, undefined, undefined, "primary"),
      requireDetectedUnconfiguredDrive(value.recoveryPath, undefined, undefined, "recovery"),
    ]);
    const manifest = await generateSplitKeystores(
      primaryPath, recoveryPath, value.authPassword, value.fallbackPassword,
    );
    return { authAddress: manifest.authAddress, fallbackAddress: manifest.fallbackAddress };
  } finally {
    generating = false;
  }
});

ipcMain.handle("vorka:vault-overview", async (_event, body: unknown) => {
  const value = objectBody(body);
  const provider = await getValidatedProvider(chainFrom(value));
  const vaultAddress = getAddress(stringField(value, "vaultAddress"));
  const [state, balance] = await Promise.all([getVaultState(provider, vaultAddress), provider.getBalance(vaultAddress)]);
  return { ...state, operationalNonce: state.operationalNonce.toString(), governanceNonce: state.governanceNonce.toString(),
    emergencyNonce: state.emergencyNonce.toString(), nativeBalance: formatEther(balance), vaultAddress };
});

ipcMain.handle("vorka:create-vault", async (_event, body: unknown) => {
  const value = objectBody(body);
  const provider = await getValidatedProvider(chainFrom(value));
  const primaryPath = stringField(value, "primaryPath");
  const manifest = await readAddressManifest(primaryPath);
  const auth = await unlockAuthKeystore(primaryPath, stringField(value, "password"));
  const vaultAddress = await createVault(
    getAddress(stringField(value, "factoryAddress")),
    getAddress(stringField(value, "beneficiary")),
    manifest.fallbackAddress,
    manifest.authAddress,
    manifest.generationId,
    auth.connect(provider),
  );
  return { vaultAddress };
});

ipcMain.handle("vorka:withdraw-native", async (_event, body: unknown) => {
  const value = objectBody(body);
  const chain = chainFrom(value);
  const provider = await getValidatedProvider(chain);
  const primaryPath = stringField(value, "primaryPath");
  const vaultAddress = getAddress(stringField(value, "vaultAddress"));
  const state = await getVaultState(provider, vaultAddress);
  if (state.frozen) throw new Error("Vault is frozen; use the recovery flow before withdrawing");
  const auth = await unlockAuthKeystore(primaryPath, stringField(value, "password"));
  if (auth.address !== state.authAddress) throw new Error("This primary key does not control the selected Vault");
  const amount = parseEther(stringField(value, "amount"));
  if (amount <= 0n) throw new Error("Withdrawal amount must be greater than zero");
  const deadline = await signingDeadline(provider);
  const signature = await signWithdraw(auth, { chainId: chain.chainId, vaultAddress }, ZeroAddress, amount, deadline, state.operationalNonce);
  const txHash = await submitWithdraw(vaultAddress, ZeroAddress, amount, deadline, signature, auth.connect(provider));
  return { txHash };
});

ipcMain.handle("vorka:freeze-vault", async (_event, body: unknown) => {
  const value = objectBody(body), chain = chainFrom(value);
  const provider = await getValidatedProvider(chain);
  const vaultAddress = getAddress(stringField(value, "vaultAddress"));
  const recoveryPath = stringField(value, "recoveryPath");
  const state = await getVaultState(provider, vaultAddress);
  if (state.frozen) return { alreadyFrozen: true };
  const fallback = await unlockFallbackKeystore(recoveryPath, stringField(value, "recoveryPassword"));
  if (fallback.address !== state.fallbackAddress) throw new Error("This recovery key does not control the selected Vault");
  const deadline = await signingDeadline(provider);
  const signature = await signFreeze(fallback, { chainId: chain.chainId, vaultAddress }, deadline, state.emergencyNonce);
  const txHash = await submitFreeze(vaultAddress, deadline, signature, fallback.connect(provider));
  return { txHash, alreadyFrozen: false };
});

ipcMain.handle("vorka:replace-primary", async (_event, body: unknown) => {
  const value = objectBody(body), chain = chainFrom(value);
  const provider = await getValidatedProvider(chain);
  const vaultAddress = getAddress(stringField(value, "vaultAddress"));
  const recoveryPath = stringField(value, "recoveryPath");
  const requestedReplacement = stringField(value, "replacementPath");
  const recoveryPassword = stringField(value, "recoveryPassword");
  let state = await getVaultState(provider, vaultAddress);
  const fallback = await unlockFallbackKeystore(recoveryPath, recoveryPassword);
  if (fallback.address !== state.fallbackAddress) throw new Error("This recovery key does not control the selected Vault");
  if (!state.frozen) {
    const freezeDeadline = await signingDeadline(provider);
    const freezeSignature = await signFreeze(fallback, { chainId: chain.chainId, vaultAddress }, freezeDeadline, state.emergencyNonce);
    await submitFreeze(vaultAddress, freezeDeadline, freezeSignature, fallback.connect(provider));
    state = await getVaultState(provider, vaultAddress);
  }
  const detectedReplacement = (await detectVorkaDrives()).find((drive) => drive.path === requestedReplacement);
  if (!detectedReplacement) throw new Error("The replacement USB is no longer connected or is not provisioned");
  let manifest;
  if (detectedReplacement.configured && detectedReplacement.role === "primary") {
    manifest = await readAddressManifest(requestedReplacement);
    const recoveryManifest = await readAddressManifest(recoveryPath);
    if (manifest.generationId !== recoveryManifest.generationId || manifest.fallbackAddress !== recoveryManifest.fallbackAddress) {
      throw new Error("This replacement primary is not paired with the selected recovery key");
    }
  } else {
    const replacementPath = await requireDetectedUnconfiguredDrive(requestedReplacement, undefined, undefined, "primary");
    manifest = await generateReplacementAuth(
      replacementPath, recoveryPath, stringField(value, "newPrimaryPassword"), recoveryPassword,
    );
  }
  if (manifest.authAddress === state.authAddress) throw new Error("Select a new primary key, not the currently authorized key");
  const deadline = await signingDeadline(provider);
  const signature = await signModifyIdentity(
    fallback, { chainId: chain.chainId, vaultAddress }, ZeroAddress, ZeroAddress, manifest.authAddress,
    deadline, state.governanceNonce,
  );
  const txHash = await submitModifyIdentity(
    vaultAddress, ZeroAddress, ZeroAddress, manifest.authAddress, deadline, signature, fallback.connect(provider),
  );
  return { txHash, newAuthAddress: manifest.authAddress };
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on("window-all-closed", () => app.quit());
