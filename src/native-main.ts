import { app, BrowserWindow, ipcMain } from "electron";
import path from "node:path";
import { generateKeystores } from "./keystore.js";
import { detectVorkaDrives, requireDetectedUnconfiguredDrive } from "./setup.js";

let generating = false;

function createWindow(): void {
  const window = new BrowserWindow({
    width: 820,
    height: 780,
    minWidth: 620,
    minHeight: 640,
    show: false,
    title: "Vorka",
    backgroundColor: "#080b10",
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
  window.once("ready-to-show", () => window.show());
}

ipcMain.handle("vorka:list-drives", () => detectVorkaDrives());
ipcMain.handle("vorka:generate", async (_event, body: unknown) => {
  if (generating) throw new Error("Key generation is already running");
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Invalid setup request");
  const value = body as Record<string, unknown>;
  if (typeof value.drivePath !== "string" ||
      typeof value.authPassword !== "string" ||
      typeof value.fallbackPassword !== "string") {
    throw new Error("Missing setup fields");
  }
  generating = true;
  try {
    const drivePath = await requireDetectedUnconfiguredDrive(value.drivePath);
    const manifest = await generateKeystores(drivePath, value.authPassword, value.fallbackPassword);
    return { authAddress: manifest.authAddress, fallbackAddress: manifest.fallbackAddress };
  } finally {
    generating = false;
  }
});

app.whenReady().then(() => {
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});
app.on("window-all-closed", () => app.quit());
