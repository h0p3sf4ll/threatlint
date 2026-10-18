/* global marked, DOMPurify */
'use strict';

// Ask Threatlint: conversations with the configured model over the shared runner socket.
// app.js owns the socket and settings and publishes them via threatlint:context.
(() => {
  const $ = id => document.getElementById(id);
  const SUGGESTIONS = {
    workspace: ['Where is user input reaching a database query?', 'Which routes are missing an authorization check?', 'What secrets or credentials are in this repo?'],
    report: ['What should I fix first, and why?', 'Which findings could be false positives?', 'Write a PR description for the fixes.'],
    finding: ['How do I fix this? Show the code change.', 'Write a regression test for this.', 'Is this exploitable in practice?'],
    scan: ['Which runtime finding is most serious?', 'Which source file causes the failed access-control assertion?', 'How do I add the missing security headers?'],
  };
  const state = { context: null, threads: [], current: null, about: { type: 'workspace', label: 'This workspace' }, pending: null };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = String(text);
    return node;
  }
  function markdown(node, text) {
    if (!window.marked || !window.DOMPurify) { node.textContent = text; return; }
    node.innerHTML = DOMPurify.sanitize(marked.parse(String(text), { gfm: true }), { USE_PROFILES: { html: true }, FORBID_TAGS: ['img', 'style', 'form', 'input', 'button', 'iframe', 'object'], FORBID_ATTR: ['style', 'srcset'] });
    for (const anchor of node.querySelectorAll('a')) { if (!(anchor.getAttribute('href') || '').startsWith('https://')) anchor.removeAttribute('href'); else { anchor.target = '_blank'; anchor.rel = 'noopener noreferrer'; } }
  }
  async function api(url, options = {}) {
    const response = await fetch(url, { cache: 'no-store', ...options });
    if (response.status === 204) return null;
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `Request failed (${response.status})`);
    return payload;
  }

  function renderContext() {
    $('chat-context').textContent = state.about.label;
    $('chat-clear-context').hidden = state.about.type === 'workspace' || !!state.current;
    const suggestions = $('chat-suggestions'); suggestions.replaceChildren();
    if (state.current?.messages?.length) return;
    for (const text of SUGGESTIONS[state.about.type] || SUGGESTIONS.workspace) {
      const chip = el('button', 'chat-chip', text); chip.type = 'button';
      chip.addEventListener('click', () => { $('chat-input').value = text; send(); });
      suggestions.append(chip);
    }
  }
  function renderStatus() {
    const context = state.context;
    const model = context?.settings?.model;
    $('chat-model-tag').textContent = model ? `${context.settings.provider.toUpperCase()} · ${model}` : 'MODEL NOT SET';
    const blocked = !context?.session ? 'Open a repository first. Threatlint answers by reading your code.' : !context.ready ? 'Choose a model (and approve remote sharing for cloud models) in Model & settings.' : !context.connected ? 'Reconnecting to the local runner…' : '';
    $('chat-send').disabled = !!blocked || !!state.pending;
    $('chat-input').disabled = !!blocked;
    $('chat-input').placeholder = blocked || 'Ask about a finding, a file, or a fix… (Enter to send, Shift+Enter for a new line)';
  }
  function message(role, content, extra = '') {
    const item = el('li', `chat-message ${role}${extra}`);
    item.append(el('span', 'chat-role', role === 'user' ? 'You' : 'Threatlint'));
    const body = el('div', 'chat-body markdown');
    if (role === 'assistant') markdown(body, content); else body.textContent = content;
    item.append(body);
    $('chat-messages').append(item);
    item.scrollIntoView({ block: 'end' });
    return { item, body };
  }
  function renderMessages() {
    $('chat-messages').replaceChildren();
    for (const item of state.current?.messages || []) message(item.role, item.content);
    if (!state.current?.messages?.length) {
      const empty = el('li', 'chat-empty');
      empty.append(el('strong', '', 'Ask anything about your code’s security.'), el('span', '', 'Answers cite file:line, propose a fix, and include a test. Threatlint reads your repo; it never edits it.'));
      $('chat-messages').append(empty);
    }
    renderContext();
  }
  async function loadThreads() {
    const sessionId = state.context?.session?.id;
    state.threads = sessionId ? await api(`/api/conversations?sessionId=${encodeURIComponent(sessionId)}`).catch(() => []) : [];
    const list = $('chat-thread-list'); list.replaceChildren();
    for (const thread of state.threads) {
      const row = el('li', `chat-thread${thread.id === state.current?.id ? ' selected' : ''}`);
      const open = el('button', 'chat-thread-open'); open.type = 'button';
      open.append(el('strong', '', thread.title), el('small', '', `${thread.context?.label || 'Workspace'} · ${Math.ceil(thread.messageCount / 2)} question${thread.messageCount > 2 ? 's' : ''}`));
      open.addEventListener('click', () => openThread(thread.id));
      const remove = el('button', 'icon-button', '×'); remove.type = 'button'; remove.setAttribute('aria-label', `Delete conversation ${thread.title}`);
      remove.addEventListener('click', async () => { await api(`/api/conversations/${encodeURIComponent(thread.id)}`, { method: 'DELETE' }); if (state.current?.id === thread.id) newThread(); loadThreads(); });
      row.append(open, remove); list.append(row);
    }
    if (!state.threads.length) list.append(el('li', 'operations-empty-note', state.context?.session ? 'No conversations yet.' : 'Open a repository to start.'));
  }
  async function openThread(id) {
    state.current = await api(`/api/conversations/${encodeURIComponent(id)}`);
    state.about = state.current.context || { type: 'workspace', label: 'This workspace' };
    renderMessages(); loadThreads();
  }
  function newThread(about = { type: 'workspace', label: 'This workspace' }) {
    state.current = null; state.about = about; renderMessages(); loadThreads(); $('chat-input').focus();
  }

  function send() {
    const question = $('chat-input').value.trim();
    const context = state.context;
    if (!question || state.pending || !context?.socket || context.socket.readyState !== 1 || $('chat-send').disabled) return;
    $('chat-input').value = '';
    $('chat-messages').querySelector('.chat-empty')?.remove();
    $('chat-suggestions').replaceChildren();
    message('user', question);
    const reply = message('assistant', '', ' streaming');
    reply.body.textContent = 'Reading your code…';
    state.pending = { reply, text: '', tools: el('ul', 'chat-tools') };
    reply.item.append(state.pending.tools);
    $('chat-stop').hidden = false; renderStatus();
    const { context: about } = { context: state.about };
    context.socket.send(JSON.stringify({ action: 'chat', ...context.settings, sessionId: context.session.id, question,
      ...(state.current ? { conversationId: state.current.id } : { context: about.type === 'workspace' ? { type: 'workspace' } : about }) }));
    document.dispatchEvent(new CustomEvent('threatlint:asked'));
  }
  function finishPending() { state.pending = null; $('chat-stop').hidden = true; renderStatus(); }

  function onEvent(event) {
    const pending = state.pending;
    if (!pending) return;
    if (event.type === 'chat_start') { state.current = { ...(state.current || {}), ...event.conversation, messages: state.current?.messages || [] }; }
    if (event.type === 'chat_tool') pending.tools.append(el('li', '', `${event.tool} ${event.detail}`));
    if (event.type === 'chat_chunk') { pending.text += event.text; pending.reply.body.textContent = pending.text; }
    if (event.type === 'chat_complete') {
      pending.reply.item.classList.remove('streaming'); markdown(pending.reply.body, event.message.content);
      finishPending(); openThread(event.conversationId).catch(() => {});
    }
    if (event.type === 'chat_error') {
      pending.reply.item.classList.remove('streaming'); pending.reply.item.classList.add('error');
      pending.reply.body.textContent = event.message || 'The answer could not be completed.';
      finishPending();
    }
  }

  function initialize() {
    if (!$('view-chat')) return;
    $('chat-form').addEventListener('submit', event => { event.preventDefault(); send(); });
    $('chat-input').addEventListener('keydown', event => { if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) { event.preventDefault(); send(); } });
    $('chat-new').addEventListener('click', () => newThread());
    $('chat-clear-context').addEventListener('click', () => newThread());
    $('chat-stop').addEventListener('click', () => state.context?.socket?.send(JSON.stringify({ action: 'chat_cancel' })));
    document.addEventListener('threatlint:chat-event', event => onEvent(event.detail));
    document.addEventListener('threatlint:context', event => {
      const previous = state.context?.session?.id;
      state.context = event.detail; renderStatus();
      if (previous !== event.detail.session?.id) { state.current = null; state.about = { type: 'workspace', label: 'This workspace' }; renderMessages(); loadThreads(); }
    });
    document.addEventListener('threatlint:ask', event => {
      const { context, question } = event.detail;
      newThread(context);
      if (question) $('chat-input').value = question;
    });
    document.addEventListener('threatlint:view', event => { if (event.detail.view === 'chat') { loadThreads(); $('chat-input').focus(); } });
    renderMessages();
    document.dispatchEvent(new CustomEvent('threatlint:request-context'));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialize, { once: true });
  else initialize();
})();
