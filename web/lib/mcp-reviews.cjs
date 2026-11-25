'use strict';

/** Profile-owned background jobs. MCP transports may close between start and polling. */
const crypto = require('node:crypto');
const { HttpError } = require('./http.cjs');

const SECRET_KEY = /(?:api.?key|token|secret|password|authorization|private.?key|credential)/i;
const EVENT_FIELDS = ['agentId', 'participantId', 'stage', 'workerId', 'tool', 'n', 'label', 'skills', 'message',
  'agentIds', 'execution', 'provider', 'model', 'scopeCount', 'reference', 'references', 'disposition', 'findingId', 'done', 'cancelled'];
const REPORT_FIELDS = ['id', 'sessionId', 'agentId', 'label', 'title', 'timestamp', 'hasDocx'];
const copy = value => structuredClone(value);

function createMcpReviews({ pipeline, store, scannerBatch, conversations, maxJobs = 25, maxEvents = 250,
  maxEventBytes = 256 * 1024, maxConcurrent = 3 }) {
  const jobs = new Map(), pending = new Set();
  let closed = false;
  const workspace = sessionId => {
    if (typeof sessionId !== 'string' || !store.sessions.has(sessionId)) throw new HttpError('Workspace not found in this profile', 404);
  };
  const jobFor = (sessionId, id) => {
    workspace(sessionId);
    const job = jobs.get(id);
    if (!job || job.sessionId !== sessionId) throw new HttpError('Job not found in this workspace', 404);
    return job;
  };
  const summary = job => ({ id: job.id, sessionId: job.sessionId, kind: job.kind, status: job.status,
    startedAt: job.startedAt, finishedAt: job.finishedAt, agentIds: [...job.agentIds], reports: copy(job.reports),
    ...(job.conversationId ? { conversationId: job.conversationId } : {}), ...(job.error ? { error: job.error } : {}) });
  function bounded(value, fallback, maximum, minimum = 0) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new HttpError('Invalid pagination limit or cursor');
    return value;
  }
  function trim() {
    while (jobs.size >= maxJobs) {
      const oldest = [...jobs.values()].find(job => job.finishedAt !== null);
      if (!oldest) throw new HttpError('Review job capacity reached; wait for a running job', 429);
      jobs.delete(oldest.id);
    }
  }
  function start(message, kind = 'review') {
    if (closed) throw new HttpError('Review jobs are closing', 503);
    workspace(message?.sessionId);
    if (!['review', 'scanner_review', 'conversation'].includes(kind)) throw new HttpError('Unknown job kind');
    const service = { review: pipeline, scanner_review: scannerBatch, conversation: conversations }[kind];
    if (!service) throw new HttpError('This review workflow is unavailable', 503);
    message = copy(message);
    if (kind === 'conversation' && message.conversationId && conversations.get(message.conversationId).sessionId !== message.sessionId) {
      throw new HttpError('Conversation not found in this workspace', 404);
    }
    if ([...jobs.values()].filter(job => job.finishedAt === null).length >= maxConcurrent) throw new HttpError('Too many active review jobs', 429);
    trim();
    const controller = new AbortController();
    const job = { id: crypto.randomUUID(), sessionId: message.sessionId, kind, status: 'running', startedAt: Date.now(),
      finishedAt: null, agentIds: Array.isArray(message.agentIds) ? message.agentIds.filter(id => typeof id === 'string').slice(0, 22).map(id => id.slice(0, 200)) : [],
      reports: [], events: [], eventBytes: 0, cursor: 0, controller };
    jobs.set(job.id, job);
    // Values are kept only for the active call, never attached to a job or its public snapshot.
    const secrets = new Set();
    function collect(value, depth = 0) {
      if (!value || typeof value !== 'object' || depth > 10) return;
      for (const [key, item] of Object.entries(value)) {
        if (SECRET_KEY.test(key) && typeof item === 'string' && item) secrets.add(item);
        else if (item && typeof item === 'object') collect(item, depth + 1);
      }
    }
    collect(message);
    function safe(value, depth = 0) {
      if (depth > 10) return '[TRUNCATED]';
      if (typeof value === 'string') {
        let text = value.replace(/(?:sk-|ghp_|github_pat_)[\w-]+/g, '[REDACTED]');
        for (const secret of secrets) text = text.split(secret).join('[REDACTED]');
        return text.slice(0, 4000);
      }
      if (Array.isArray(value)) return value.slice(0, 100).map(item => safe(item, depth + 1));
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100)
        .filter(([key]) => !SECRET_KEY.test(key) && !['input', 'preview', 'text', 'detail'].includes(key))
        .map(([key, item]) => [key, safe(item, depth + 1)]));
      return value;
    }
    function record(event) {
      if (!event || typeof event.type !== 'string' || ['text_chunk', 'chat_chunk'].includes(event.type)) return;
      const entry = { type: safe(event.type) };
      for (const key of EVENT_FIELDS) if (Object.hasOwn(event, key)) entry[key] = safe(event[key]);
      if (event.type === 'chat_error' || event.type === 'scanner_item' && event.stage === 'error') job.error = typeof entry.message === 'string' ? entry.message : 'A review item failed; inspect the saved results';
      if (event.conversationId) job.conversationId = safe(event.conversationId);
      if (event.conversation?.id) job.conversationId = safe(event.conversation.id);
      if (job.conversationId && event.type.startsWith('chat_')) entry.conversationId = job.conversationId;
      const report = event.report || (event.type === 'agent_complete' ? event : null);
      if (report?.id) {
        const reference = Object.fromEntries(REPORT_FIELDS.filter(key => Object.hasOwn(report, key)).map(key => [key, safe(report[key])]));
        entry.report = reference;
        if (!job.reports.some(item => item.id === reference.id)) job.reports.push(reference);
      }
      entry.cursor = ++job.cursor;
      entry.at = Date.now();
      const bytes = Buffer.byteLength(JSON.stringify(entry));
      if (bytes > maxEventBytes) { delete entry.execution; delete entry.references; entry.truncated = true; }
      job.events.push(entry); job.eventBytes += Buffer.byteLength(JSON.stringify(entry));
      while (job.events.length > maxEvents || job.eventBytes > maxEventBytes) job.eventBytes -= Buffer.byteLength(JSON.stringify(job.events.shift()));
    }
    // Defer invocation so synchronous and asynchronous service validation share the same failure path.
    const promise = Promise.resolve().then(() => kind === 'conversation'
      ? conversations.ask(message, record, controller.signal)
      : service.run(message, record, controller)).then(status => {
      job.status = controller.signal.aborted || status === 'cancelled' ? 'cancelled'
        : status === 'error' || job.error ? 'failed' : 'completed';
    }, error => {
      job.status = controller.signal.aborted ? 'cancelled' : 'failed';
      if (!controller.signal.aborted) job.error = safe(error?.message || 'Review could not complete');
    }).finally(() => {
      job.finishedAt = Date.now();
      record({ type: 'job_complete', message: job.status });
      secrets.clear(); pending.delete(promise); delete job.controller;
    });
    pending.add(promise);
    return summary(job);
  }
  return {
    start,
    list(sessionId, options = {}) {
      workspace(sessionId);
      const offset = bounded(options.offset, 0, 10000), limit = bounded(options.limit, 25, 100, 1);
      const selected = [...jobs.values()].filter(job => job.sessionId === sessionId).reverse();
      return { jobs: selected.slice(offset, offset + limit).map(summary), total: selected.length,
        nextOffset: offset + limit < selected.length ? offset + limit : null };
    },
    get(sessionId, id, options = {}) {
      const job = jobFor(sessionId, id), after = bounded(options.after, 0, Number.MAX_SAFE_INTEGER), limit = bounded(options.limit, 100, 100, 1);
      if (after > job.cursor) throw new HttpError('The event cursor is beyond this job history');
      const available = job.events.filter(event => event.cursor > after), events = available.slice(0, limit);
      const oldest = job.events[0]?.cursor || job.cursor + 1;
      return { ...summary(job), events: copy(events), nextCursor: events.at(-1)?.cursor ?? Math.max(after, oldest - 1),
        hasMore: available.length > events.length, eventsTruncated: after < oldest - 1, latestCursor: job.cursor };
    },
    cancel(sessionId, id) {
      const job = jobFor(sessionId, id);
      if (job.controller && job.finishedAt === null) { job.status = 'cancelling'; job.controller.abort(); }
      return summary(job);
    },
    async close() {
      closed = true;
      for (const job of jobs.values()) job.controller?.abort();
      await Promise.allSettled([...pending]);
    },
  };
}

module.exports = { createMcpReviews };
