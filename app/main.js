// Gorilla Yapps desktop app: a window that opens the Gorilla Yapps website.
// Change SITE below if the website ever moves to a new address.
const { app, BrowserWindow, shell, session, desktopCapturer, Menu, Tray, ipcMain, nativeImage } = require("electron");
const path = require("path");

const SITE = "https://gorilla-yapp.vercel.app/";
const ORIGIN = new URL(SITE).origin;
const isOurs = url => typeof url === "string" && (url === ORIGIN || url.startsWith(ORIGIN + "/"));

const OFFLINE = `<!doctype html><meta charset="utf-8"><title>Gorilla Yapps</title>
<body style="margin:0;height:100vh;display:grid;place-items:center;background:#222a24;color:#dce3dc;font-family:Segoe UI,system-ui,sans-serif;text-align:center">
<div><h1 style="margin:8px 0">Can't reach Gorilla Yapps</h1>
<p style="color:#b3bfb4">Check your internet, then try again.</p>
<button onclick="location.href='${SITE}'" style="font:inherit;font-weight:700;padding:10px 22px;border:0;border-radius:6px;background:#2e7d32;color:#fff;cursor:pointer">Try again</button></div>`;

if (!app.requestSingleInstanceLock()) app.quit();
// Windows only shows notifications for apps that have an id
app.setAppUserModelId("app.gorillayapps.desktop");

let tray = null, quitting = false;
function showWin() { if (!win) { createWindow(); return; } if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
function makeTray() {
  if (tray) return;
  tray = new Tray(nativeImage.createFromPath(path.join(__dirname, "icon.png")).resize({ width: 16, height: 16 }));
  tray.setToolTip("Gorilla Yapps");
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: "Open Gorilla Yapps", click: showWin },
    { type: "separator" },
    { label: "Quit", click: () => { quitting = true; app.quit(); } }
  ]));
  tray.on("click", showWin);
}
ipcMain.on("gy-show", showWin);

let win = null;
function createWindow() {
  win = new BrowserWindow({
    width: 1280, height: 820, minWidth: 380, minHeight: 520,
    title: "Gorilla Yapps", backgroundColor: "#222a24", autoHideMenuBar: true,
    icon: path.join(__dirname, "icon.png"),
    webPreferences: { contextIsolation: true, sandbox: true, spellcheck: true, backgroundThrottling: false, preload: path.join(__dirname, "preload.js") }
  });
  win.webContents.setUserAgent(win.webContents.getUserAgent() + " GorillaYappsDesktop/1.0");
  win.loadURL(SITE);
  // links to other websites open in the normal browser
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (isOurs(url)) return { action: "allow" };
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (e, url) => {
    if (isOurs(url) || url.startsWith("data:")) return;
    e.preventDefault();
    if (/^https?:\/\//.test(url)) shell.openExternal(url);
  });
  win.webContents.on("did-fail-load", (e, code, desc, url, isMainFrame) => {
    if (isMainFrame && code !== -3) win.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(OFFLINE));
  });
  // closing the window keeps Gorilla Yapps in the tray so DMs and pings still show up
  win.on("close", e => { if (!quitting && tray) { e.preventDefault(); win.hide(); } });
  win.on("closed", () => { win = null; });
}

app.on("second-instance", showWin);
app.on("before-quit", () => { quitting = true; });

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  const ses = session.defaultSession;
  // microphone, camera, notifications and screen share are allowed only for Gorilla Yapps itself
  const allowed = ["media", "notifications", "display-capture", "fullscreen", "clipboard-sanitized-write"];
  ses.setPermissionRequestHandler((wc, permission, callback, details) => {
    callback(isOurs((details && details.requestingUrl) || wc.getURL()) && allowed.includes(permission));
  });
  ses.setPermissionCheckHandler((wc, permission, origin) => isOurs(origin) && allowed.concat(["media"]).includes(permission));
  ses.setDisplayMediaRequestHandler((request, callback) => {
    desktopCapturer.getSources({ types: ["screen", "window"] })
      .then(sources => callback(sources.length ? { video: sources[0] } : {}))
      .catch(() => callback({}));
  }, { useSystemPicker: true });
  createWindow();
  makeTray();
  app.on("activate", () => { if (!BrowserWindow.getAllWindows().length) createWindow(); });
});

app.on("window-all-closed", () => { if (process.platform !== "darwin") app.quit(); });
