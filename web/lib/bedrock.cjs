'use strict';

/** Bedrock API-key authentication is separate from Anthropic keys and Claude Code's login. */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { HttpError } = require('./http.cjs');

const text = value => typeof value === 'string' ? value.trim() : '';

function settingsEnv(home) {
  try {
    const env = JSON.parse(fs.readFileSync(path.join(home, '.claude', 'settings.json'), 'utf8')).env;
    return env && typeof env === 'object' ? env : {};
  } catch { return {}; }
}

function bedrockRegion(region, env = process.env, settings = {}) {
  const value = text(region) || text(env.AWS_REGION) || text(env.AWS_DEFAULT_REGION)
    || text(settings.AWS_REGION) || text(settings.AWS_DEFAULT_REGION) || 'us-east-1';
  // Only a region name may enter the hostname. Never accept a URL, port, or path from the client.
  if (value.length > 40 || !/^[a-z]{2,5}(?:-[a-z0-9]+)+-\d{1,2}$/.test(value)) {
    throw new HttpError('Enter an AWS region such as us-east-1');
  }
  return value;
}

function bedrockCredential(sessionKey, { env = process.env, home = os.homedir(), region } = {}) {
  const settings = settingsEnv(home);
  const resolvedRegion = bedrockRegion(region, env, settings);
  const suffix = resolvedRegion.startsWith('cn-') ? 'amazonaws.com.cn' : 'amazonaws.com';
  const endpoint = { region: resolvedRegion, baseUrl: `https://bedrock-runtime.${resolvedRegion}.${suffix}/anthropic` };
  if (text(sessionKey)) return { key: text(sessionKey), source: 'session', ...endpoint };
  for (const [values, prefix] of [[env, ''], [settings, '~/.claude/settings.json ']]) {
    for (const name of ['AWS_BEARER_TOKEN_BEDROCK', 'BEDROCK_API_KEY']) {
      if (text(values[name])) return { key: text(values[name]), source: prefix ? `${prefix}(${name})` : name, ...endpoint };
    }
  }
  return { key: '', source: null, ...endpoint };
}

/** Daybreak Blue is currently Mantle-only and offered in us-east-2. Keep its endpoint
 * separate from the Anthropic Messages endpoint used for Claude on Bedrock. */
function daybreakBedrockCredential(sessionKey, { env = process.env, home = os.homedir(), region } = {}) {
  if (text(region) && bedrockRegion(region, env) !== 'us-east-2') {
    throw new HttpError('Daybreak Blue on Bedrock is available in us-east-2; choose that AWS region');
  }
  const credential = bedrockCredential(sessionKey, { env, home, region: 'us-east-2' });
  return { ...credential, baseUrl: 'https://bedrock-mantle.us-east-2.api.aws/openai/v1' };
}

module.exports = { bedrockCredential, daybreakBedrockCredential, bedrockRegion };
