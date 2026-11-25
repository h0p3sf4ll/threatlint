'use strict';

/** Shared, headless model discovery. Only public source labels and model IDs leave this module. */
const catalog = require('./model-catalog.cjs');
const { modelPolicy } = require('./model-policy.cjs');
const { validateBaseUrl } = require('./providers.cjs');
const { HttpError } = require('./http.cjs');

const MODEL_PROVIDERS = Object.freeze(['claude', 'claude-code', 'bedrock', 'daybreak', 'daybreak-bedrock', 'openai', 'copilot', 'codex', 'lmstudio']);
const sourceLabel = value => typeof value === 'string' ? value.slice(0, 2000) : null;
const redact = (value, secrets) => {
  let text = String(value);
  for (const secret of secrets) if (typeof secret === 'string' && secret) text = text.split(secret).join('[REDACTED]');
  return text;
};

async function providerSources(integrations = {}) {
  const sources = await (integrations.credentialSources || catalog.credentialSources)();
  const policy = (integrations.modelPolicy || modelPolicy)();
  return {
    providers: Object.fromEntries(MODEL_PROVIDERS.map(provider => [provider, sourceLabel(sources[provider])])),
    modelPolicy: { scan: sourceLabel(policy.scan), general: sourceLabel(policy.general) },
  };
}

/** Compatible with POST /api/models and GET /api/lmstudio/models request/response fields. */
async function listConfiguredModels(input = {}, integrations = {}) {
  const provider = input.provider;
  if (!MODEL_PROVIDERS.includes(provider)) throw new HttpError('Unknown model provider');
  if (input.key !== undefined && (typeof input.key !== 'string' || input.key.length > 4096)) throw new HttpError('Model key must be at most 4096 characters');
  const secrets = [input.key];
  const publicResult = value => {
    // Explicit field selection excludes credential keys, CLI login tokens and provider response metadata.
    const result = {};
    if (Object.hasOwn(value, 'source')) result.source = value.source == null ? null : redact(sourceLabel(value.source), secrets);
    if (value.transport) result.transport = value.transport;
    if (value.manual !== undefined) result.manual = value.manual;
    if (value.region) result.region = value.region;
    result.models = (Array.isArray(value.models) ? value.models : []).slice(0, 2000).flatMap(model => {
      if (typeof model === 'string') return [redact(model, secrets).slice(0, 2000)];
      if (!model || typeof model.id !== 'string') return [];
      return [{ id: redact(model.id, secrets).slice(0, 2000), name: redact(typeof model.name === 'string' ? model.name : model.id, secrets).slice(0, 2000) }];
    });
    return result;
  };
  try {
    if (provider === 'lmstudio') {
      const baseUrl = validateBaseUrl(input.baseUrl);
      let data;
      try {
        const response = await (integrations.fetchImpl || fetch)(`${baseUrl}/models`, { signal: AbortSignal.timeout(5000), redirect: 'error' });
        if (!response.ok) throw new Error(`Model server returned HTTP ${response.status}`);
        data = await response.json();
      } catch (error) { throw new HttpError(`Cannot load model list: ${error.message}`, 503); }
      return publicResult({ models: (data.data || []).map(model => model.id).filter(id => typeof id === 'string') });
    }
    if (provider === 'claude-code') {
      const status = await (integrations.claudeCodeStatus || require('./claude-code.cjs').status)();
      if (!status.installed) throw new HttpError('Claude Code is not installed. Install it, run `claude` once to sign in, then reload.', 401);
      if (!status.loggedIn) throw new HttpError('Claude Code is not signed in. Run `claude` in a terminal and sign in, then reload.', 401);
      return publicResult({ source: status.source, models: await catalog.listModels(provider, {}) });
    }
    if (provider === 'codex') {
      const status = await (integrations.codexStatus || require('./codex.cjs').status)();
      if (!status.installed) throw new HttpError('Codex CLI is not installed. Install it, run `codex login`, then retry.', 401);
      if (!status.loggedIn) throw new HttpError('Codex CLI is not signed in. Run `codex login` in a terminal and retry.', 401);
      return publicResult({ source: status.source, models: [] });
    }
    const credential = await (integrations.resolveKey || catalog.resolveKey)(provider, input.key, { region: input.bedrockRegion });
    secrets.push(credential.key);
    if (provider === 'daybreak' && !credential.key) {
      const status = await (integrations.codexStatus || require('./codex.cjs').status)();
      if (!status.installed) throw new HttpError('Daybreak Blue needs your Codex login or an OpenAI API key. Install Codex and sign in, or enter an API key in Settings.', 401);
      if (!status.loggedIn) throw new HttpError('Sign in to Codex with your Daybreak Blue account (`codex login`), or enter an OpenAI API key in Settings.', 401);
      return publicResult({ source: status.source, transport: 'codex', models: await catalog.listModels(provider, { transport: 'codex' }) });
    }
    return publicResult({ source: credential.source, models: await catalog.listModels(provider, credential, { fetchImpl: integrations.fetchImpl }),
      ...(['bedrock', 'daybreak-bedrock'].includes(provider) ? { manual: provider === 'bedrock', region: credential.region } : {}) });
  } catch (error) {
    throw new HttpError(redact(error.message || 'Cannot load model list', secrets).slice(0, 2000), error.status || 500);
  }
}

module.exports = { MODEL_PROVIDERS, providerSources, listConfiguredModels };
