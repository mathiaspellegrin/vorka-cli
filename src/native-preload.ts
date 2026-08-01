import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("vorka", Object.freeze({
  listDrives: () => ipcRenderer.invoke("vorka:list-drives"),
  generatePassword: () => ipcRenderer.invoke("vorka:generate-password"),
  backupDevice: (request: unknown) => ipcRenderer.invoke("vorka:backup-device", request),
  restoreDevice: (request: unknown) => ipcRenderer.invoke("vorka:restore-device", request),
  generate: (request: unknown) => ipcRenderer.invoke("vorka:generate", request),
  vaultOverview: (request: unknown) => ipcRenderer.invoke("vorka:vault-overview", request),
  createVault: (request: unknown) => ipcRenderer.invoke("vorka:create-vault", request),
  reviewWithdrawNative: (request: unknown) => ipcRenderer.invoke("vorka:review-withdraw-native", request),
  confirmWithdrawNative: (request: unknown) => ipcRenderer.invoke("vorka:confirm-withdraw-native", request),
  freezeVault: (request: unknown) => ipcRenderer.invoke("vorka:freeze-vault", request),
  replacePrimary: (request: unknown) => ipcRenderer.invoke("vorka:replace-primary", request),
}));
