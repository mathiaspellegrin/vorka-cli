import { app, BrowserWindow, dialog, ipcMain, session, type IpcMainInvokeEvent } from "electron";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { ZeroAddress, formatEther, getAddress, parseEther } from "ethers";
import { backupKeystores, generateReplacementAuth, generateSplitKeystores, getDeviceRole, protectVorkaDevice, readAddressManifest, restoreKeystoreBackup, unlockAuthKeystore, unlockFallbackKeystore } from "./keystore.js";
import { detectVorkaDrives, requireDetectedUnconfiguredDrive, requireUniqueProvisionedPair } from "./setup.js";
import {
  createVault,
  estimateWithdrawFee,
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
const pendingWithdrawals = new Map<string, {
  expiresAt: number; chain: ChainConfig; vaultAddress: string; amount: bigint; deadline: bigint;
  signature: string; authAddress: string; beneficiary: string; operationalNonce: bigint;
}>();
const trustedRendererUrl = pathToFileURL(path.join(__dirname, "native-ui.html")).href;

function handle(channel: string, listener: (event: IpcMainInvokeEvent, ...args: unknown[]) => unknown): void {
  ipcMain.handle(channel, (event, ...args) => {
    if (event.senderFrame?.url !== trustedRendererUrl) throw new Error("Untrusted application frame");
    return listener(event, ...args);
  });
}

function createSplashWindow(): BrowserWindow {
  const splash = new BrowserWindow({
    width: 420,
    height: 360,
    show: false,
    frame: false,
    resizable: false,
    movable: true,
    alwaysOnTop: true,
    center: true,
    backgroundColor: "#e7e2d6",
    webPreferences: { contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true },
  });
  splash.once("ready-to-show", () => splash.show());
  void splash.loadFile(path.join(__dirname, "native-splash.html"));
  return splash;
}

function createWindow(splash?: BrowserWindow): void {
  const window = new BrowserWindow({
    width: 820,
    height: 780,
    minWidth: 620,
    minHeight: 640,
    show: false,
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
  window.webContents.on("will-attach-webview", (event) => event.preventDefault());
  window.once("ready-to-show", () => {
    window.maximize();
    window.show();
    if (splash && !splash.isDestroyed()) splash.close();
  });
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

handle("vorka:list-drives", async () => {
  const drives = await detectVorkaDrives();
  await Promise.all(drives.map((drive) => protectVorkaDevice(drive.path)));
  return drives;
});
handle("vorka:generate-password", () => randomBytes(24).toString("base64url"));
handle("vorka:backup-device", async (_event, body: unknown) => {
  const value = objectBody(body), requestedSource = stringField(value, "sourcePath");
  const candidates = (await detectVorkaDrives()).filter((drive) => drive.path === requestedSource && drive.configured && !drive.damaged);
  if (candidates.length !== 1) throw new Error("The backup source is no longer exactly one configured Vorka device");
  const role = await getDeviceRole(requestedSource);
  if (role !== "primary" && role !== "recovery") throw new Error("Back up Primary and Recovery separately");
  const manifest = await readAddressManifest(requestedSource);
  const selection = await dialog.showOpenDialog({ title: `Choose where to store the ${role.toUpperCase()} encrypted backup`,
    properties: ["openDirectory", "createDirectory", "promptToCreate"] });
  if (selection.canceled || selection.filePaths.length !== 1) return { canceled: true };
  const folder = `Vorka-${role.toUpperCase()}-backup-${manifest.generationId.slice(2, 14)}`;
  const destination = path.join(selection.filePaths[0], folder);
  await backupKeystores(requestedSource, destination);
  return { canceled: false, role, destination, generationId: manifest.generationId };
});

handle("vorka:restore-device", async (_event, body: unknown) => {
  const value = objectBody(body), requestedDestination = stringField(value, "destinationPath");
  const detected = (await detectVorkaDrives()).filter((drive) => drive.path === requestedDestination && !drive.configured && !drive.damaged);
  if (detected.length !== 1 || (detected[0].provisionedRole !== "primary" && detected[0].provisionedRole !== "recovery")) {
    throw new Error("Select exactly one fresh provisioned Vorka device as the restore destination");
  }
  const expectedRole = detected[0].provisionedRole;
  const destinationPath = await requireDetectedUnconfiguredDrive(requestedDestination, undefined, undefined, expectedRole);
  const selection = await dialog.showOpenDialog({ title: `Select the Vorka ${expectedRole.toUpperCase()} backup folder`,
    properties: ["openDirectory"] });
  if (selection.canceled || selection.filePaths.length !== 1) return { canceled: true };
  const manifest = await restoreKeystoreBackup(selection.filePaths[0], destinationPath, expectedRole);
  return { canceled: false, role: expectedRole, generationId: manifest.generationId };
});
handle("vorka:generate", async (_event, body: unknown) => {
  if (generating) throw new Error("Key generation is already running");
  const value = objectBody(body);
  if (typeof value.primaryPath !== "string" || typeof value.recoveryPath !== "string" ||
      typeof value.authPassword !== "string" ||
      typeof value.fallbackPassword !== "string") {
    throw new Error("Missing setup fields");
  }
  generating = true;
  try {
    const { primaryPath, recoveryPath } = await requireUniqueProvisionedPair(value.primaryPath, value.recoveryPath);
    const manifest = await generateSplitKeystores(
      primaryPath, recoveryPath, value.authPassword, value.fallbackPassword,
    );
    return { authAddress: manifest.authAddress, fallbackAddress: manifest.fallbackAddress };
  } finally {
    generating = false;
  }
});

handle("vorka:vault-overview", async (_event, body: unknown) => {
  const value = objectBody(body);
  const provider = await getValidatedProvider(chainFrom(value));
  const vaultAddress = getAddress(stringField(value, "vaultAddress"));
  const [state, balance] = await Promise.all([getVaultState(provider, vaultAddress), provider.getBalance(vaultAddress)]);
  return { ...state, operationalNonce: state.operationalNonce.toString(), governanceNonce: state.governanceNonce.toString(),
    emergencyNonce: state.emergencyNonce.toString(), nativeBalance: formatEther(balance), vaultAddress };
});

handle("vorka:create-vault", async (_event, body: unknown) => {
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

handle("vorka:review-withdraw-native", async (_event, body: unknown) => {
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
  const fee = await estimateWithdrawFee(provider, vaultAddress, ZeroAddress, amount, deadline, signature, auth.address);
  const reviewId = randomBytes(32).toString("hex"), expiresAt = Date.now() + 2 * 60_000;
  pendingWithdrawals.set(reviewId, { expiresAt, chain, vaultAddress, amount, deadline, signature, authAddress: auth.address,
    beneficiary: state.owner, operationalNonce: state.operationalNonce });
  return { reviewId, expiresAt, action: "Withdraw native funds", chainId: chain.chainId, vaultAddress,
    beneficiary: state.owner, amount: formatEther(amount), gasLimit: fee.gasLimit.toString(),
    maxFeePerGas: fee.maxFeePerGas.toString(), estimatedFee: formatEther(fee.estimatedFee),
    operationalNonce: state.operationalNonce.toString(), deadline: deadline.toString() };
});

handle("vorka:confirm-withdraw-native", async (_event, body: unknown) => {
  const value = objectBody(body), reviewId = stringField(value, "reviewId");
  const pending = pendingWithdrawals.get(reviewId);
  pendingWithdrawals.delete(reviewId);
  if (!pending || pending.expiresAt < Date.now()) throw new Error("Transaction review expired; review the withdrawal again");
  const provider = await getValidatedProvider(pending.chain);
  const state = await getVaultState(provider, pending.vaultAddress);
  if (state.frozen || state.authAddress !== pending.authAddress || state.owner !== pending.beneficiary ||
      state.operationalNonce !== pending.operationalNonce) {
    throw new Error("Vault state changed after review; review the withdrawal again");
  }
  const auth = await unlockAuthKeystore(stringField(value, "primaryPath"), stringField(value, "password"));
  if (auth.address !== pending.authAddress) throw new Error("This primary key no longer controls the reviewed Vault");
  const txHash = await submitWithdraw(pending.vaultAddress, ZeroAddress, pending.amount, pending.deadline, pending.signature, auth.connect(provider));
  return { txHash };
});

handle("vorka:freeze-vault", async (_event, body: unknown) => {
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

handle("vorka:replace-primary", async (_event, body: unknown) => {
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
  app.setAppUserModelId("com.fluxpad.vorka");
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  const splash = createSplashWindow();
  createWindow(splash);
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on("window-all-closed", () => app.quit());
