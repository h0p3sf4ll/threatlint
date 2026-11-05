'use strict';

/** Connector-neutral, locally persisted finding snapshots for metrics. No credentials or raw tracker rows are stored. */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const SOURCE_META = Object.freeze({
  'servicenow-avit': { label: 'ServiceNow AVIT', kind: 'defect-tracker' },
  defectdojo: { label: 'DefectDojo', kind: 'defect-tracker' },
});
const SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNSPECIFIED']);
const DISPOSITIONS = new Set(['OPEN', 'FALSE POSITIVE', 'REMEDIATED', 'RESOLVED']);

function bounded(value, length) { return String(value ?? '').trim().slice(0, length); }
function time(value, fallback) {
  const number = typeof value === 'number' ? value : Date.parse(String(value || ''));
  return Number.isFinite(number) && number > 0 && number < Date.now() + 86400000 ? number : fallback;
}
function week(timestamp) {
  const date = new Date(timestamp);
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - ((date.getUTCDay() + 6) % 7));
  return date.toISOString().slice(0, 10);
}
function fact(source, item, syncedAt) {
  const id = bounded(item?.id, 100);
  if (!id) throw new Error(`${SOURCE_META[source].label} returned a finding without an ID`);
  const timestamp = time(item.timestamp, syncedAt);
  const severity = bounded(item.severity, 20).toUpperCase();
  const disposition = bounded(item.disposition, 30).toUpperCase();
  return {
    source, reportId: null, agentId: source, agentLabel: SOURCE_META[source].label, category: 'Defect tracker',
    sessionId: null, workspace: bounded(item.workspace, 120) || SOURCE_META[source].label,
    timestamp, day: new Date(timestamp).toISOString().slice(0, 10), week: week(timestamp),
    severity: SEVERITIES.has(severity) ? severity : 'UNSPECIFIED', confidence: 'TRACKER',
    disposition: DISPOSITIONS.has(disposition) ? disposition : 'OPEN',
    findingId: id, rule: bounded(item.rule, 120) || 'n/a', title: bounded(item.title, 300) || id,
    fingerprint: bounded(item.fingerprint, 150).startsWith(source + '|') ? bounded(item.fingerprint, 150)
      : source + '|' + (bounded(item.fingerprint, 150) || id), hasEvidence: item.hasEvidence === true,
  };
}

function field(row, name) {
  const raw = row?.[name];
  if (raw && typeof raw === 'object') return bounded(raw.display_value || raw.value, 400);
  return bounded(raw, 400);
}
function rawField(row, name) {
  const raw = row?.[name];
  return bounded(raw && typeof raw === 'object' ? raw.value : raw, 400);
}
function avitSeverity(row) {
  const label = [field(row, 'severity'), field(row, 'risk_rating'), field(row, 'priority')].join(' ').toLowerCase();
  for (const [word, severity] of [['critical', 'CRITICAL'], ['high', 'HIGH'], ['medium', 'MEDIUM'], ['moderate', 'MEDIUM'], ['low', 'LOW'], ['informational', 'INFO']]) {
    if (label.split(/[^a-z]+/).includes(word)) return severity;
  }
  return 'UNSPECIFIED';
}
function avitDisposition(row) {
  const state = field(row, 'state').toLowerCase();
  const substate = field(row, 'substate').toLowerCase();
  const stateCode = rawField(row, 'state');
  const substateCode = rawField(row, 'substate');
  if (/false.?positive/.test(substate) ||
      (stateCode === (process.env.THREATLINT_SNOW_FP_STATE || '3') && substateCode === (process.env.THREATLINT_SNOW_FP_SUBSTATE || '3'))) return 'FALSE POSITIVE';
  if (/remediated|fixed/.test(state) || /remediated|fixed/.test(substate)) return 'REMEDIATED';
  if (/closed|resolved/.test(state) || stateCode === (process.env.THREATLINT_SNOW_FP_STATE || '3')) return 'RESOLVED';
  return 'OPEN';
}
function avitTimestamp(row, fallback) {
  for (const name of ['first_found', 'sys_created_on', 'sys_updated_on', 'last_found']) {
    const value = rawField(row, name) || field(row, name);
    if (!value) continue;
    const date = /^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(value) ? `${value.replace(' ', 'T')}Z` : value;
    const parsed = time(date, 0);
    if (parsed) return parsed;
  }
  return fallback;
}
function avitMetricsItems(rows, syncedAt = Date.now()) {
  return rows.map(({ id, sysId, fields }) => ({
    id, title: field(fields, 'short_description') || id, severity: avitSeverity(fields),
    disposition: avitDisposition(fields), timestamp: avitTimestamp(fields, syncedAt),
    workspace: field(fields, 'u_repository') || field(fields, 'repository') || field(fields, 'application_release') || field(fields, 'cmdb_ci') || 'ServiceNow AVIT',
    rule: field(fields, 'rule') || field(fields, 'scanner') || field(fields, 'source') || field(fields, 'u_security_finding_source') || 'n/a',
    fingerprint: sysId || id,
    hasEvidence: !!(field(fields, 'source_file') && field(fields, 'line_number')) || /:\d+\b/.test(field(fields, 'location')),
  }));
}

function createTrackerMetrics(directory) {
  const file = directory ? path.join(directory, 'tracker-metrics.json') : null;
  let snapshots = {};
  if (file && fs.existsSync(file)) {
    try {
      const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const source of Object.keys(SOURCE_META)) {
        const entry = saved?.[source];
        if (!entry || !Array.isArray(entry.items)) continue;
        const syncedAt = time(entry.lastSyncedAt, Date.now());
        snapshots[source] = { lastSyncedAt: syncedAt, createdThrough: /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/.test(entry.createdThrough) ? entry.createdThrough : null,
          scope: source === 'servicenow-avit' && entry.scope?.type === 'avits' && Array.isArray(entry.scope.avits)
            ? { type: 'avits', avits: entry.scope.avits.map(value => bounded(value, 30)).filter(Boolean).slice(0, 500) }
            : source === 'servicenow-avit' && entry.scope?.type === 'query' && typeof entry.scope.query === 'string'
              ? { type: 'query', query: bounded(entry.scope.query, 2000) } : null,
          items: [...new Map(entry.items.map(item => [bounded(item.findingId, 100), fact(source, { ...item, id: item.findingId }, syncedAt)])).values()] };
      }
    } catch { snapshots = {}; }
  }
  function persist(next) {
    if (!file) return;
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const temporary = `${file}.${crypto.randomUUID()}.tmp`;
    try {
      fs.writeFileSync(temporary, JSON.stringify(next), { mode: 0o600 });
      fs.renameSync(temporary, file);
    } finally { if (fs.existsSync(temporary)) fs.rmSync(temporary, { force: true }); }
  }
  return {
    facts: () => Object.values(snapshots).flatMap(entry => entry.items),
    snapshot(source) { return snapshots[source] || null; },
    replace(source, items, { createdThrough = null, scope = null } = {}) {
      if (!SOURCE_META[source]) throw new Error('Unknown defect tracker');
      if (!Array.isArray(items)) throw new Error('Defect tracker findings must be a list');
      const syncedAt = Date.now();
      const normalized = [...new Map(items.map(item => [bounded(item?.id, 100), fact(source, item, syncedAt)])).values()];
      const cutoff = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/.test(createdThrough) ? createdThrough : null;
      const next = { ...snapshots, [source]: { lastSyncedAt: syncedAt, createdThrough: cutoff,
        scope: source === 'servicenow-avit' ? scope : null, items: normalized } };
      persist(next);
      snapshots = next;
      return { source, count: normalized.length, lastSyncedAt: syncedAt, createdThrough: cutoff,
        scope: source === 'servicenow-avit' ? scope : null };
    },
  };
}

module.exports = { SOURCE_META, createTrackerMetrics, avitMetricsItems, avitSeverity, avitDisposition };
