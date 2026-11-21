'use strict';

const crypto = require('node:crypto');

/** Reuse an activated account without persisting a credential in the connection summary. */
function createSavedSourceActivator(scm) {
  const cached = new Map(), pending = new Map();
  return async function activate(connection) {
    const fingerprint = crypto.createHash('sha256').update(JSON.stringify([
      connection.provider, connection.organization || '', connection.token,
    ])).digest('hex');
    const live = scm.list();
    for (const [key, id] of cached) if (!live.some(item => item.id === id)) cached.delete(key);
    const existing = live.find(item => item.id === cached.get(fingerprint));
    if (existing) return existing;
    if (pending.has(fingerprint)) return pending.get(fingerprint);
    const operation = Promise.resolve().then(() => scm.connect({ provider: connection.provider,
      token: connection.token, organization: connection.organization || undefined })).then(result => {
      cached.set(fingerprint, result.id);
      return result;
    }).finally(() => pending.delete(fingerprint));
    pending.set(fingerprint, operation);
    return operation;
  };
}

module.exports = { createSavedSourceActivator };
