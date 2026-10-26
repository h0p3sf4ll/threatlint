'use strict';

/**
 * Organization-specific settings (SSO portal, Parameter Store names, Semgrep deployment), shared with the
 * CLI's threatlint/org_config.py. Each value comes from its environment variable, then ~/.threatlint/org.json.
 * Nothing organization-specific is built in; an unset Parameter Store name means it is not read from there.
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ENV = {
  ssoUrl: 'THREATLINT_AWS_SSO_PORTAL_URL',
  snowClientIdParameter: 'THREATLINT_SNOW_CLIENT_ID_PARAMETER',
  snowClientSecretParameter: 'THREATLINT_SNOW_CLIENT_SECRET_PARAMETER',
  semgrepTokenParameter: 'THREATLINT_SEMGREP_TOKEN_PARAMETER',
  semgrepDeployment: 'THREATLINT_SEMGREP_DEPLOYMENT',
};

function orgPath() { return path.join(process.env.THREATLINT_HOME || path.join(os.homedir(), '.threatlint'), 'org.json'); }

function orgValue(key) {
  if (process.env[ENV[key]]) return process.env[ENV[key]].trim();
  try {
    const saved = JSON.parse(fs.readFileSync(orgPath(), 'utf8'));
    return saved && typeof saved === 'object' ? String(saved[key] || '').trim() : '';
  } catch { return ''; }
}

module.exports = { ENV, orgPath, orgValue };
