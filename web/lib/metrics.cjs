'use strict';

/**
 * Metrics and dashboards over locally saved reports and runtime scans.
 *
 * collectFacts({ sessions, runtimeScans, agents }) -> flat finding facts, one per
 *   (report, finding), each { source, agentId, agentLabel, category, sessionId,
 *   workspace, timestamp, day, severity, confidence, disposition, findingId,
 *   title, fingerprint, hasEvidence }.
 * aggregate(facts, { metric, groupBy, filters }) -> { rows: [{ key, value }] }.
 * overview(facts, sessions) -> KPI summary used by the default dashboard.
 * createDashboardStore(directory) -> { list, get, save, remove } persisting
 *   user-defined dashboards as JSON (no report content is copied into them).
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNSPECIFIED'];
const SEVERITY_WEIGHT = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, INFO: 0, UNSPECIFIED: 1 };
const DIMENSIONS = ['severity', 'agent', 'category', 'workspace', 'day', 'week', 'disposition', 'confidence', 'source', 'rule'];
const METRICS = ['findings', 'reports', 'riskScore', 'uniqueFindings', 'evidenceCoverage'];
const CHARTS = ['kpi', 'bar', 'hbar', 'line', 'donut', 'table', 'heatmap'];

function isoDay(timestamp) { return new Date(timestamp).toISOString().slice(0, 10); }
function isoWeek(timestamp) {
  const date = new Date(timestamp);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - ((date.getUTCDay() + 6) % 7));
  return date.toISOString().slice(0, 10);
}

function collectFacts({ sessions, runtimeScans = [], agents = {} }) {
  const facts = [];
  for (const session of sessions.values()) {
    const workspace = session.repoPath.split(/[\\/]/).filter(Boolean).at(-1) || session.repoPath;
    for (const report of session.reports) {
      const agent = agents[report.agentId];
      const base = { source: 'report', reportId: report.id, agentId: report.agentId, agentLabel: agent?.label || report.label || report.agentId,
        category: agent?.category || 'Analysis', sessionId: session.id, workspace, timestamp: report.timestamp, day: isoDay(report.timestamp), week: isoWeek(report.timestamp) };
      if (!report.findings?.length) { facts.push({ ...base, empty: true }); continue; }
      for (const finding of report.findings) {
        facts.push({ ...base, severity: finding.severity || 'UNSPECIFIED', confidence: finding.confidence || 'UNSPECIFIED', disposition: finding.disposition || 'OPEN',
          findingId: finding.id, rule: finding.id.replace(/-\d+$/, ''), title: finding.title, fingerprint: finding.fingerprint || `${report.agentId}|${finding.id}`, hasEvidence: !!finding.evidence?.length });
      }
    }
  }
  for (const scan of runtimeScans) {
    const base = { source: 'runtime', reportId: scan.id, agentId: 'runtime-observer', agentLabel: 'Runtime observer', category: 'Runtime', sessionId: null,
      workspace: scan.target, timestamp: scan.startedAt, day: isoDay(scan.startedAt), week: isoWeek(scan.startedAt) };
    if (!scan.findings.length) { facts.push({ ...base, empty: true }); continue; }
    for (const finding of scan.findings) {
      facts.push({ ...base, severity: finding.severity, confidence: 'OBSERVED', disposition: 'OPEN', findingId: finding.id, rule: finding.rule, title: finding.title,
        fingerprint: `${scan.target}|${finding.rule}|${finding.path}`, hasEvidence: true });
    }
  }
  return facts;
}

function matches(fact, filters = {}) {
  for (const [key, value] of Object.entries(filters)) {
    if (value === undefined || value === '' || (Array.isArray(value) && !value.length)) continue;
    if (key === 'since') { if (fact.timestamp < Date.parse(value)) return false; continue; }
    const actual = key === 'agent' ? fact.agentId : fact[key];
    if (Array.isArray(value) ? !value.includes(actual) : actual !== value) return false;
  }
  return true;
}

function keyOf(fact, dimension) {
  if (dimension === 'agent') return fact.agentLabel;
  return fact[dimension] ?? 'n/a';
}

function aggregate(facts, { metric = 'findings', groupBy = 'severity', filters = {} } = {}) {
  if (!METRICS.includes(metric)) throw new Error(`Unknown metric ${metric}`);
  if (groupBy && !DIMENSIONS.includes(groupBy)) throw new Error(`Unknown dimension ${groupBy}`);
  const selected = facts.filter(fact => matches(fact, filters));
  const groups = new Map();
  for (const fact of selected) {
    const key = groupBy ? keyOf(fact, groupBy) : 'total';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(fact);
  }
  const value = items => {
    const findings = items.filter(fact => !fact.empty);
    switch (metric) {
      case 'findings': return findings.length;
      case 'reports': return new Set(items.map(fact => fact.reportId)).size;
      case 'riskScore': return findings.filter(fact => fact.disposition !== 'FALSE POSITIVE' && fact.disposition !== 'REMEDIATED' && fact.disposition !== 'RESOLVED').reduce((sum, fact) => sum + SEVERITY_WEIGHT[fact.severity], 0);
      case 'uniqueFindings': return new Set(findings.map(fact => fact.fingerprint)).size;
      case 'evidenceCoverage': return findings.length ? Math.round(100 * findings.filter(fact => fact.hasEvidence).length / findings.length) : 0;
      default: return 0;
    }
  };
  let rows = [...groups].map(([key, items]) => ({ key: String(key), value: value(items) }));
  if (groupBy === 'severity') rows.sort((a, b) => SEVERITY_ORDER.indexOf(a.key) - SEVERITY_ORDER.indexOf(b.key));
  else if (groupBy === 'day' || groupBy === 'week') rows.sort((a, b) => a.key.localeCompare(b.key));
  else rows.sort((a, b) => b.value - a.value || a.key.localeCompare(b.key));
  if (groupBy === 'severity') rows = rows.filter(row => row.key !== 'n/a');
  return { metric, groupBy, rows, total: value(selected) };
}

/** Two-dimensional counts for heatmaps: rows x columns. */
function matrix(facts, { rows = 'agent', columns = 'severity', filters = {} } = {}) {
  if (!DIMENSIONS.includes(rows) || !DIMENSIONS.includes(columns)) throw new Error('Unknown dimension');
  const cells = new Map();
  const rowKeys = new Set(), columnKeys = new Set();
  for (const fact of facts.filter(item => !item.empty && matches(item, filters))) {
    const row = keyOf(fact, rows), column = keyOf(fact, columns);
    rowKeys.add(row); columnKeys.add(column);
    cells.set(`${row}\u0000${column}`, (cells.get(`${row}\u0000${column}`) || 0) + 1);
  }
  const sortColumns = columns === 'severity' ? [...columnKeys].sort((a, b) => SEVERITY_ORDER.indexOf(a) - SEVERITY_ORDER.indexOf(b)) : [...columnKeys].sort();
  return { rows: [...rowKeys].sort(), columns: sortColumns, cells: Object.fromEntries(cells) };
}

function overview(facts, sessions) {
  const findings = facts.filter(fact => !fact.empty);
  const open = findings.filter(fact => !['FALSE POSITIVE', 'REMEDIATED', 'RESOLVED'].includes(fact.disposition));
  const day = 24 * 60 * 60 * 1000;
  const recent = findings.filter(fact => fact.timestamp >= Date.now() - 7 * day).length;
  const previous = findings.filter(fact => fact.timestamp < Date.now() - 7 * day && fact.timestamp >= Date.now() - 14 * day).length;
  return {
    workspaces: sessions.size, reports: new Set(facts.filter(fact => fact.source === 'report').map(fact => fact.reportId)).size,
    runtimeScans: new Set(facts.filter(fact => fact.source === 'runtime').map(fact => fact.reportId)).size,
    findings: findings.length, open: open.length, critical: open.filter(fact => fact.severity === 'CRITICAL').length, high: open.filter(fact => fact.severity === 'HIGH').length,
    riskScore: open.reduce((sum, fact) => sum + SEVERITY_WEIGHT[fact.severity], 0),
    falsePositiveRate: findings.length ? Math.round(100 * findings.filter(fact => fact.disposition === 'FALSE POSITIVE').length / findings.length) : 0,
    evidenceCoverage: findings.length ? Math.round(100 * findings.filter(fact => fact.hasEvidence).length / findings.length) : 0,
    last7Days: recent, previous7Days: previous,
    topRules: aggregate(facts, { metric: 'findings', groupBy: 'rule' }).rows.slice(0, 5),
  };
}

const DEFAULT_DASHBOARD = Object.freeze({
  id: 'default', name: 'Security posture', builtIn: true,
  widgets: [
    { id: 'w1', title: 'Open risk score', chart: 'kpi', metric: 'riskScore', groupBy: null, size: 1 },
    { id: 'w2', title: 'Findings', chart: 'kpi', metric: 'findings', groupBy: null, size: 1 },
    { id: 'w3', title: 'Evidence coverage %', chart: 'kpi', metric: 'evidenceCoverage', groupBy: null, size: 1 },
    { id: 'w4', title: 'Reports & scans', chart: 'kpi', metric: 'reports', groupBy: null, size: 1 },
    { id: 'w5', title: 'Findings by severity', chart: 'donut', metric: 'findings', groupBy: 'severity', size: 2 },
    { id: 'w6', title: 'Findings over time', chart: 'line', metric: 'findings', groupBy: 'day', size: 2 },
    { id: 'w7', title: 'Risk by specialist', chart: 'hbar', metric: 'riskScore', groupBy: 'agent', size: 2 },
    { id: 'w8', title: 'Specialist × severity', chart: 'heatmap', metric: 'findings', groupBy: 'agent', columns: 'severity', size: 2 },
    { id: 'w9', title: 'Risk by workspace', chart: 'table', metric: 'riskScore', groupBy: 'workspace', size: 4 },
  ],
});

function validateDashboard(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('A dashboard object is required');
  const name = typeof input.name === 'string' ? input.name.trim() : '';
  if (!name || name.length > 80) throw new Error('Name the dashboard (1–80 characters)');
  if (!Array.isArray(input.widgets) || input.widgets.length > 24) throw new Error('A dashboard has at most 24 widgets');
  const widgets = input.widgets.map((widget, index) => {
    if (!widget || typeof widget !== 'object') throw new Error(`Widget ${index + 1} is invalid`);
    const title = typeof widget.title === 'string' && widget.title.trim() ? widget.title.trim().slice(0, 80) : `Widget ${index + 1}`;
    if (!CHARTS.includes(widget.chart)) throw new Error(`Widget ${index + 1}: unknown chart type`);
    if (!METRICS.includes(widget.metric)) throw new Error(`Widget ${index + 1}: unknown metric`);
    const groupBy = widget.chart === 'kpi' ? null : widget.groupBy;
    if (groupBy !== null && !DIMENSIONS.includes(groupBy)) throw new Error(`Widget ${index + 1}: unknown dimension`);
    if (widget.chart === 'heatmap' && !DIMENSIONS.includes(widget.columns)) throw new Error(`Widget ${index + 1}: choose heatmap columns`);
    const filters = {};
    for (const key of ['severity', 'agent', 'category', 'workspace', 'source', 'disposition', 'since']) {
      const value = widget.filters?.[key];
      if (value === undefined || value === '') continue;
      if (typeof value !== 'string' || value.length > 300) throw new Error(`Widget ${index + 1}: invalid ${key} filter`);
      filters[key] = value;
    }
    return { id: typeof widget.id === 'string' && /^[\w-]{1,40}$/.test(widget.id) ? widget.id : `w${index + 1}`, title, chart: widget.chart, metric: widget.metric, groupBy,
      ...(widget.chart === 'heatmap' ? { columns: widget.columns } : {}), size: [1, 2, 4].includes(widget.size) ? widget.size : 2, filters };
  });
  return { name, widgets };
}

function createDashboardStore(directory) {
  const file = directory ? path.join(directory, 'dashboards.json') : null;
  let dashboards = [];
  if (file && fs.existsSync(file)) {
    try { dashboards = JSON.parse(fs.readFileSync(file, 'utf8')).filter(item => item?.id && item?.name); } catch { dashboards = []; }
  }
  function persist() {
    if (!file) return;
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(temporary, JSON.stringify(dashboards, null, 2), { mode: 0o600 });
    fs.renameSync(temporary, file);
  }
  return {
    list: () => [DEFAULT_DASHBOARD, ...dashboards],
    get: id => (id === 'default' ? DEFAULT_DASHBOARD : dashboards.find(item => item.id === id)),
    save(input, id) {
      const valid = validateDashboard(input);
      if (id === 'default') throw new Error('The built-in dashboard is read-only. Duplicate it to customize');
      if (id) {
        const existing = dashboards.find(item => item.id === id);
        if (!existing) throw new Error('Dashboard not found');
        Object.assign(existing, valid, { updatedAt: Date.now() });
        persist();
        return existing;
      }
      if (dashboards.length >= 50) throw new Error('At most 50 custom dashboards');
      const dashboard = { id: crypto.randomUUID(), ...valid, createdAt: Date.now(), updatedAt: Date.now() };
      dashboards.push(dashboard);
      persist();
      return dashboard;
    },
    remove(id) {
      const before = dashboards.length;
      dashboards = dashboards.filter(item => item.id !== id);
      if (dashboards.length !== before) persist();
      return dashboards.length !== before;
    },
  };
}

module.exports = { collectFacts, aggregate, matrix, overview, createDashboardStore, validateDashboard, DEFAULT_DASHBOARD, DIMENSIONS, METRICS, CHARTS, SEVERITY_WEIGHT };
