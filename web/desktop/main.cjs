'use strict';

const { app, BrowserWindow, dialog, ipcMain, Menu, shell, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const { watch, readFileSync } = require('node:fs');

let mainWindow;
let workbench;
let origin;
let quitting = false;

// Packaged builds carry the stamp written by scripts/desktop-sync.cjs; dev runs use live source.
function buildInfo() {
  if (!app.isPackaged) return { fingerprint: 'source', commit: 'live', version: app.getVersion() };
  try { return JSON.parse(readFileSync(path.join(process.resourcesPath, 'build-info.json'), 'utf8')); } catch { return { fingerprint: 'unstamped', commit: 'unknown', version: app.getVersion() }; }
}

// desktop:dev reloads the UI when public/ changes and relaunches when the runner code changes,
// so the desktop window always shows the current shared code.
function watchSources() {
  const root = path.resolve(__dirname, '..');
  let timer;
  const schedule = action => { clearTimeout(timer); timer = setTimeout(action, 150); };
  watch(path.join(root, 'public'), { recursive: true }, () => schedule(() => mainWindow?.webContents.reloadIgnoringCache()));
  for (const target of ['lib', 'server.js', 'desktop']) {
    watch(path.join(root, target), { recursive: true }, () => schedule(() => { app.relaunch(); quitting = true; workbench.close().finally(() => app.exit(0)); }));
  }
}

function trustedFrame(event) {
  if (!mainWindow || event.sender !== mainWindow.webContents || event.senderFrame !== event.sender.mainFrame || !event.senderFrame.url.startsWith(`${origin}/`)) throw new Error('Untrusted desktop request');
}

async function createWindow() {
  mainWindow = new BrowserWindow({
    title: 'Threatlint', width: 1500, height: 980, minWidth: 940, minHeight: 680,
    backgroundColor: '#101617', show: false,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), nodeIntegration: false,
      contextIsolation: true, sandbox: true, webSecurity: true, allowRunningInsecureContent: false, devTools: !app.isPackaged },
  });
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Only downloads from our own server or an explicit HTTPS link can leave the renderer.
    if (url.startsWith(`${origin}/api/report/`)) mainWindow.webContents.downloadURL(url);
    else if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!url.startsWith(`${origin}/`)) event.preventDefault();
  });
  mainWindow.webContents.on('will-attach-webview', event => event.preventDefault());
  mainWindow.once('ready-to-show', () => mainWindow.show());
  mainWindow.on('closed', () => { mainWindow = null; });
  await mainWindow.loadURL(origin);
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });
  app.whenReady().then(async () => {
    if (app.isPackaged) process.env.THREATLINT_DATA_DIR = path.join(process.resourcesPath, 'data');
    // The factory below owns the desktop store; the default exported server stays unbound.
    process.env.THREATLINT_STATE_DIR = path.join(app.getPath('userData'), 'workbench');
    process.env.THREATLINT_BUILD_INFO = JSON.stringify(buildInfo());
    const { createWorkbench } = require('../server.js');
    workbench = createWorkbench({ storageDir: process.env.THREATLINT_STATE_DIR });
    await new Promise((resolve, reject) => { workbench.server.once('error', reject); workbench.server.listen(0, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${workbench.server.address().port}`;
    session.defaultSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    session.defaultSession.setPermissionCheckHandler(() => false);
    // Renderer code and external report content cannot make outbound requests.
    session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
      const local = details.url.startsWith(`${origin}/`) || details.url.startsWith(origin.replace('http:', 'ws:') + '/');
      callback({ cancel: !local });
    });
    ipcMain.handle('threatlint:select-repository', async event => {
      trustedFrame(event);
      const result = await dialog.showOpenDialog(mainWindow, { title: 'Choose a repository to review', properties: ['openDirectory'] });
      return result.canceled ? null : result.filePaths[0];
    });
    ipcMain.handle('threatlint:select-findings', async event => {
      trustedFrame(event);
      const result = await dialog.showOpenDialog(mainWindow, { title: 'Attach scanner findings', properties: ['openFile'], filters: [{ name: 'Security findings', extensions: ['sarif', 'json', 'md', 'txt'] }] });
      if (result.canceled) return null;
      const filename = result.filePaths[0];
      if (!/\.(sarif|json|md|txt)$/i.test(filename)) throw new Error('Unsupported findings file');
      const stats = await fs.stat(filename);
      if (!stats.isFile() || stats.size > 5 * 1024 * 1024) throw new Error('Choose a findings file smaller than 5 MB');
      return { name: path.basename(filename), content: await fs.readFile(filename, 'utf8') };
    });
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      ...(process.platform === 'darwin' ? [{ role: 'appMenu' }] : []),
      { label: 'File', submenu: [{ label: 'Choose Repository…', accelerator: 'CmdOrCtrl+O', click: () => mainWindow?.webContents.send('threatlint:choose-repository') }, { role: 'close' }] },
      { role: 'editMenu' }, { role: 'viewMenu' }, { role: 'windowMenu' },
    ]));
    await createWindow();
    if (!app.isPackaged && process.env.THREATLINT_DESKTOP_WATCH === '1') watchSources();
    app.on('activate', () => {
      if (!mainWindow) createWindow().catch(error => dialog.showErrorBox('Could not open Threatlint', error.message));
    });
  }).catch(error => { dialog.showErrorBox('Threatlint could not start', error.message); app.quit(); });
  app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
  app.on('before-quit', event => {
    if (quitting || !workbench) return;
    event.preventDefault();
    quitting = true;
    workbench.close().finally(() => app.quit());
  });
}