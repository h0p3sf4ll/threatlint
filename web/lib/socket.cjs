'use strict';

/**
 * WebSocket protocol. One connection runs at most one pipeline or scanner batch and one conversation answer.
 * Actions: run_pipeline, cancel, run_scanner_batch, chat, chat_cancel, and for finding triage run_avit_batch,
 * avit_batch_attach, avit_batch_cancel. A finding-triage run belongs to the Workbench (avit-runs.cjs), not to the
 * connection: closing the page leaves it running, and any page attaches to replay it and follow its progress.
 */

const { WebSocketServer } = require('ws');
const { localRequest } = require('./http.cjs');

const MAX_PAYLOAD = 7 * 1024 * 1024;

function attachSocket(server, { pipeline, conversations, avitRuns, scannerBatch }) {
  const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_PAYLOAD });
  server.on('upgrade', (req, socket, head) => {
    if (!localRequest(req, server)) { socket.write('HTTP/1.1 403 Forbidden\r\n\r\n'); socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, ws => wss.emit('connection', ws, req));
  });

  wss.on('connection', ws => {
    const jobs = { pipeline: null, chat: null };
    const send = message => { if (ws.readyState === 1) ws.send(JSON.stringify(message)); };
    const abortAll = () => { jobs.pipeline?.abort(); jobs.chat?.abort(); };

    async function runPipeline(message) {
      if (jobs.pipeline) { send({ type: 'error', message: 'A pipeline is already running on this connection' }); return; }
      const controller = new AbortController();
      jobs.pipeline = controller;
      try {
        const status = await pipeline.run(message, send, controller);
        if (status === 'cancelled') send({ type: 'cancelled' });
        send({ type: 'pipeline_complete', status });
      } catch (error) { send({ type: 'error', message: error.message }); }
      finally { jobs.pipeline = null; }
    }

    // This page receives a finding-triage run's events while it is open; the run itself never depends on it.
    const follow = event => send(event);
    function runAvitBatch(message) {
      try { avitRuns.start(message, follow); }
      catch (error) { send({ type: 'avit_batch_error', code: error.code, message: error.message }); }
    }
    function attachAvitBatch() { send({ type: 'avit_batch_replay', ...avitRuns.attach(follow) }); }

    async function runScannerBatch(message) {
      if (jobs.pipeline) { send({ type: 'error', message: 'A review is already running on this connection' }); return; }
      const controller = new AbortController();
      jobs.pipeline = controller;
      try { await scannerBatch.run(message, send, controller); }
      catch (error) { send({ type: 'scanner_batch_error', tool: message.tool, message: error.message }); }
      finally { jobs.pipeline = null; }
    }

    async function chat(message) {
      if (jobs.chat) { send({ type: 'chat_error', message: 'Wait for the current answer or stop it first' }); return; }
      const controller = new AbortController();
      jobs.chat = controller;
      try { await conversations.ask(message, send, controller.signal); }
      catch (error) { send({ type: 'chat_error', conversationId: message.conversationId || null, message: error.message }); }
      finally { jobs.chat = null; }
    }

    const actions = {
      run_pipeline: runPipeline,
      run_avit_batch: runAvitBatch,
      avit_batch_attach: attachAvitBatch,
      avit_batch_cancel: () => send({ type: 'avit_batch_cancel_ack', accepted: avitRuns.cancel() }),
      run_scanner_batch: runScannerBatch,
      cancel: () => jobs.pipeline?.abort(),
      chat,
      chat_cancel: () => jobs.chat?.abort(),
    };

    ws.on('message', raw => {
      let message;
      try { message = JSON.parse(raw); } catch { send({ type: 'error', message: 'Invalid JSON message' }); return; }
      if (!message || typeof message !== 'object' || Array.isArray(message)) { send({ type: 'error', message: 'A structured action message is required' }); return; }
      const action = Object.hasOwn(actions, message.action) ? actions[message.action] : null;
      if (!action) { send({ type: 'error', message: 'Unknown action' }); return; }
      Promise.resolve(action(message)).catch(() => send({ type: 'error', message: 'The request could not complete' }));
    });
    const disconnect = () => { abortAll(); avitRuns.detach(follow); };
    ws.on('error', disconnect);
    ws.on('close', disconnect);
  });
  return wss;
}

module.exports = { attachSocket };
