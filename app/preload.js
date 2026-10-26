// Lets the Gorilla Yapps page bring its window back when you click a notification.
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("gyDesktop", { show: () => ipcRenderer.send("gy-show") });
