import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld("vorka", Object.freeze({
  listDrives: () => ipcRenderer.invoke("vorka:list-drives"),
  generate: (request: unknown) => ipcRenderer.invoke("vorka:generate", request),
}));
