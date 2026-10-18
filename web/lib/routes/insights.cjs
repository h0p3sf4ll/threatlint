'use strict';

/** Metrics, user-defined dashboards, in-app help, and conversation history. */

const fs = require('node:fs');
const path = require('node:path');
const { AGENTS } = require('../agents.cjs');
const { collectFacts, aggregate, matrix, overview, DIMENSIONS, METRICS, CHARTS } = require('../metrics.cjs');
const { HELP_TOPICS, TOOLTIPS, VIDEOS } = require('../help.cjs');
const { handle } = require('../http.cjs');

const MEDIA = path.join(__dirname, '../../public/media');
const CSV_COLUMNS = ['timestamp', 'source', 'workspace', 'agentId', 'category', 'findingId', 'title', 'severity', 'confidence', 'disposition', 'hasEvidence'];

// Leading = + - @ would make a spreadsheet evaluate the cell as a formula.
function csvCell(value) {
  const text = String(value ?? '').replaceAll('"', '""');
  return /^[=+\-@\t\r]/.test(text) ? `"'${text}"` : `"${text}"`;
}

function registerInsightRoutes(app, { store, history, dashboards, conversations }) {
  const facts = () => collectFacts({ sessions: store.sessions, runtimeScans: history.finished(), agents: AGENTS });

  app.get('/api/metrics/schema', (_req, res) => res.json({ dimensions: DIMENSIONS, metrics: METRICS, charts: CHARTS }));
  app.get('/api/metrics/overview', (_req, res) => res.json(overview(facts(), store.sessions)));
  app.post('/api/metrics/query', handle(req => {
    const { chart, metric, groupBy, columns, filters } = req.body || {};
    return chart === 'heatmap' ? matrix(facts(), { rows: groupBy, columns, filters }) : aggregate(facts(), { metric, groupBy: groupBy || null, filters });
  }, { fallback: 'Invalid metric query' }));
  app.get('/api/metrics/export', (_req, res) => {
    const rows = facts().filter(fact => !fact.empty).map(fact => CSV_COLUMNS.map(column => csvCell(column === 'timestamp' ? new Date(fact.timestamp).toISOString() : fact[column])).join(','));
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="threatlint-findings.csv"');
    res.send([CSV_COLUMNS.join(','), ...rows].join('\n'));
  });

  app.get('/api/dashboards', (_req, res) => res.json(dashboards.list()));
  app.post('/api/dashboards', handle(req => dashboards.save(req.body), { status: 201, fallback: 'Invalid dashboard' }));
  app.put('/api/dashboards/:id', handle(req => dashboards.save(req.body, req.params.id), { fallback: 'Invalid dashboard' }));
  app.delete('/api/dashboards/:id', (req, res) => res.status(dashboards.remove(req.params.id) ? 204 : 404).end());

  app.get('/api/help', (_req, res) => res.json({ topics: HELP_TOPICS, tooltips: TOOLTIPS,
    videos: VIDEOS.map(video => ({ ...video, available: fs.existsSync(path.join(MEDIA, video.file)) })) }));

  app.get('/api/conversations', (req, res) => res.json(conversations.list(typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined)));
  app.get('/api/conversations/:id', handle(req => conversations.get(req.params.id)));
  app.delete('/api/conversations/:id', (req, res) => res.status(conversations.remove(req.params.id) ? 204 : 404).end());
}

module.exports = { registerInsightRoutes, csvCell };
