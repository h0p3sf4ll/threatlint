'use strict';

// The splash page runs no script of its own; this preload writes status text straight into its DOM.
const { ipcRenderer } = require('electron');

ipcRenderer.on('splash:status', (_event, { title, detail }) => {
  document.getElementById('title').textContent = title;
  document.getElementById('detail').textContent = detail;
});
