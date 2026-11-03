'use strict';

/**
 * Design inputs on the Review code page: architecture and data-flow diagrams, design documents, specs, and images
 * that support a threat model. Files are uploaded to /api/design-inputs as soon as they are picked, so the user sees
 * what was understood from each one; a run sends only the returned id (window.ThreatlintDesignInputs.id()).
 * CSP-safe: DOM nodes and textContent only.
 */
(() => {
  const $ = id => document.getElementById(id);
  const MAX_FILES = 20, MAX_TOTAL = 25 * 1024 * 1024;
  const IDLE_NOTE = 'Diagrams, design docs, specs, or images · up to 20 files, 25 MB';
  const state = { files: [], bundle: null, busy: false };

  const toast = (message, error) => document.dispatchEvent(new CustomEvent('threatlint:toast', { detail: { message, error } }));
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  const base64 = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(',')[1] || '');
    reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
    reader.readAsDataURL(file);
  });
  const size = bytes => (bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`);

  function render() {
    const list = $('design-input-list');
    const summary = state.bundle?.files || [];
    list.hidden = !summary.length;
    list.replaceChildren(...summary.map((file, index) => {
      const item = el('li', 'design-input-item');
      const detail = file.image ? 'image' : `${file.chars.toLocaleString()} characters${file.truncated ? ` · ${file.truncated.toLocaleString()} truncated` : ''}`;
      item.append(el('strong', '', file.name), el('span', 'small subtle', `${file.kind} · ${detail}`));
      const remove = el('button', 'icon-button', '×');
      remove.type = 'button'; remove.setAttribute('aria-label', `Remove ${file.name}`); remove.disabled = state.busy;
      remove.addEventListener('click', () => update(state.files.filter((_, position) => position !== index)));
      item.append(remove);
      return item;
    }));
    $('design-inputs-note').textContent = state.busy ? 'Reading design inputs…' : summary.length ? `${summary.length} design input${summary.length === 1 ? '' : 's'} · used as evidence, verified against source` : IDLE_NOTE;
    $('add-design-inputs').disabled = state.busy;
  }

  /** Replaces the bundle with one built from `files` (the server extracts and validates them). */
  async function update(files) {
    const previous = state.bundle, previousFiles = state.files;
    state.files = files; state.busy = true; render();
    try {
      if (files.length > MAX_FILES) throw new Error(`Add at most ${MAX_FILES} design inputs.`);
      if (files.reduce((sum, file) => sum + file.size, 0) > MAX_TOTAL) throw new Error('Design inputs can total at most 25 MB.');
      if (!files.length) { state.bundle = null; return; }
      const body = JSON.stringify({ files: await Promise.all(files.map(async file => ({ name: file.name, content: await base64(file) }))) });
      const response = await fetch('/api/design-inputs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload.error || `Upload failed (${response.status})`);
      state.bundle = payload;
      toast(`${payload.files.length} design input${payload.files.length === 1 ? '' : 's'} ready. Agents treat them as evidence and verify them against the source.`);
    } catch (error) {
      state.files = previousFiles;
      state.bundle = previous;
      toast(error.message, true);
    } finally {
      if (previous && previous !== state.bundle) fetch(`/api/design-inputs/${encodeURIComponent(previous.id)}`, { method: 'DELETE' }).catch(() => {});
      state.busy = false; render();
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    if (!$('add-design-inputs')) return;
    $('add-design-inputs').addEventListener('click', () => $('design-input-files').click());
    $('design-input-files').addEventListener('change', event => {
      const picked = [...event.target.files];
      event.target.value = '';
      if (picked.length) void update([...state.files, ...picked]);
    });
    render();
  });

  window.ThreatlintDesignInputs = { id: () => state.bundle?.id || null, clear: () => update([]) };
})();
