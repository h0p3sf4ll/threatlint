'use strict';

/**
 * WebSocket protocol. One connection runs at most one pipeline and one conversation answer.
 * Actions: run_pipeline, cancel, run_avit_batch, chat, chat_cancel. A connection runs one pipeline or AVIT batch at a time.
 */

const { WebSocketServer } = require('ws');
const { localRequest } = require('./http.cjs');

const MAX_PAYLOAD = 7 * 1024 * 1024;

function attachSocket(server, { pipeline, conversations, avitBatch }) {
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

    async function runAvitBatch(message) {
      if (jobs.pipeline) { send({ type: 'error', message: 'A review is already running on this connection' }); return; }
      const controller = new AbortController();
      jobs.pipeline = controller;
      try { await avitBatch.run(message, send, controller); }
      catch (error) { send({ type: 'avit_batch_error', message: error.message }); }
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
    ws.on('error', abortAll);
    ws.on('close', abortAll);
  });
  return wss;
}

module.exports = { attachSocket };
