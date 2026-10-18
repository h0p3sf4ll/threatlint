'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('threatlintDesktop', Object.freeze({
  isDesktop: true,
  version: '1.0.0',
  selectRepository: () => ipcRenderer.invoke('threatlint:select-repository'),
  selectFindings: () => ipcRenderer.invoke('threatlint:select-findings'),
  onChooseRepository: callback => {
    const listener = () => callback();
    ipcRenderer.on('threatlint:choose-repository', listener);
    return () => ipcRenderer.removeListener('threatlint:choose-repository', listener);
  },
}));