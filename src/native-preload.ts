import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("vorka", Object.freeze({
  listDrives: () => ipcRenderer.invoke("vorka:list-drives"),
  generatePassword: () => ipcRenderer.invoke("vorka:generate-password"),
  generate: (request: unknown) => ipcRenderer.invoke("vorka:generate", request),
  vaultOverview: (request: unknown) => ipcRenderer.invoke("vorka:vault-overview", request),
  createVault: (request: unknown) => ipcRenderer.invoke("vorka:create-vault", request),
  withdrawNative: (request: unknown) => ipcRenderer.invoke("vorka:withdraw-native", request),
  freezeVault: (request: unknown) => ipcRenderer.invoke("vorka:freeze-vault", request),
  replacePrimary: (request: unknown) => ipcRenderer.invoke("vorka:replace-primary", request),
}));
