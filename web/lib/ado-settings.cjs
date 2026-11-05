'use strict';

/** Credential-source metadata only; neither status nor browser responses include a PAT. */
function publicAdoStatus(stdout) {
  let value;
  try { value = JSON.parse(String(stdout || '').trim()); } catch { /* older CLI or test adapter */ }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const account = value.serviceAccount || {};
    const organizations = Array.isArray(value.organizations) ? value.organizations
      .filter(item => item && typeof item.name === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(item.name))
      .map(item => ({ name: item.name, source: String(item.source || '') })) : [];
    return { hasPat: !!value.hasPat, source: typeof value.source === 'string' ? value.source : null, organizations,
      serviceAccount: { configured: !!account.configured, parameter: String(account.parameter || ''), profile: String(account.profile || ''),
        region: String(account.region || ''), organizations: Array.isArray(account.organizations) ? account.organizations.filter(name => typeof name === 'string' && /^[A-Za-z0-9][A-Za-z0-9-]{0,49}$/.test(name)) : [] } };
  }
  const sources = [...String(stdout || '').matchAll(/^Azure DevOps PAT: (.+)$/gm)].map(match => match[1]);
  return { hasPat: sources.length > 0, source: sources.join('; ') || null,
    organizations: sources.map(line => /^(.*) · ([A-Za-z0-9-]+)$/.exec(line)).filter(Boolean).map(([, source, name]) => ({ name, source })),
    serviceAccount: { configured: false, parameter: '', profile: '', region: '', organizations: [] } };
}

module.exports = { publicAdoStatus };
