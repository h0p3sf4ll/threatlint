'use strict';

const { MODEL_PROVIDERS, providerSources, listConfiguredModels } = require('./model-discovery.cjs');

function registerProviderTools({ tool, z, integrations = {} }) {
  const externalRead = { readOnly: true, openWorld: true };
  tool('get_model_providers', 'Discover supported model providers, environment/CLI credential source labels, and configured review/chat defaults. Never returns keys or login tokens.',
    {}, () => providerSources(integrations), externalRead);
  tool('list_models', 'List models available to a provider using existing environment/CLI credentials or an optional session-only key. Codex and Bedrock allow explicit model entry; LM Studio uses a validated model-server URL.', {
    provider: z.enum(MODEL_PROVIDERS), key: z.string().max(4096).optional(),
    bedrockRegion: z.string().max(40).optional(), baseUrl: z.string().min(1).max(2048).optional(),
  }, input => listConfiguredModels(input, integrations), externalRead);
  tool('get_setup_status', 'Read setup checks for ServiceNow, source control and scanner integrations using the existing CLI configuration. Returns credential availability and setup guidance, never secret values.',
    {}, async () => {
      const items = await require('./avit-batch.cjs').setupStatus(integrations.threatlintCli);
      return { items: (Array.isArray(items) ? items : []).slice(0, 100).map(item => ({ name: typeof item.name === 'string' ? item.name.slice(0, 300) : '',
        configured: item.configured === true, source: typeof item.source === 'string' ? item.source.slice(0, 2000) : null,
        fix: typeof item.fix === 'string' ? item.fix.slice(0, 2000) : '' })) };
    }, externalRead);
}

module.exports = { registerProviderTools };
