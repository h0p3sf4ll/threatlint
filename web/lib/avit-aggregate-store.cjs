'use strict';

/** Last completed all-AVIT count summary; no credentials or individual AVIT records. */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function valid(summary) {
  return summary && summary.source === 'servicenow-avit' && summary.mode === 'aggregate'
    && summary.scope === 'all-readable-avits' && Number.isSafeInteger(summary.total) && summary.total >= 0
    && typeof summary.asOf === 'string' && Number.isFinite(Date.parse(summary.asOf))
    && summary.filters && typeof summary.filters === 'object' && !Array.isArray(summary.filters)
    && ['riskRating', 'state', 'substate'].every(key => summary[key] === null ||
      (Array.isArray(summary[key]) && summary[key].length <= 100 && summary[key].every(row =>
        typeof row.key === 'string' && Number.isSafeInteger(row.count) && row.count >= 0)));
}

function createAvitAggregateStore(directory) {
  const file = directory ? path.join(directory, 'avit-aggregate.json') : null;
  let summary = null;
  if (file && fs.existsSync(file)) {
    try {
      const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (valid(saved)) summary = saved;
    } catch { /* An incomplete or invalid cache cannot become a metric. */ }
  }
  return {
    get: () => summary,
    replace(next) {
      if (!valid(next)) throw new Error('Invalid ServiceNow AVIT aggregate summary');
      if (file) {
        fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
        const temp = `${file}.${crypto.randomUUID()}.tmp`;
        try {
          fs.writeFileSync(temp, JSON.stringify(next), { mode: 0o600 });
          fs.renameSync(temp, file);
        } finally { if (fs.existsSync(temp)) fs.rmSync(temp, { force: true }); }
      }
      summary = next;
      return summary;
    },
  };
}

module.exports = { createAvitAggregateStore };
