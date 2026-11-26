'use strict';

/**
 * Reasoning effort levels each provider accepts. An empty or missing effort means "use the provider or model default",
 * so nothing is sent. Keep this list in sync with EFFORT_LEVELS in public/app.js (tests/effort.test.cjs checks it).
 *
 * - Claude API / Bedrock: output_config.effort (with adaptive thinking so the higher levels take effect)
 * - Claude Code: --effort
 * - Codex CLI: -c model_reasoning_effort=...
 * - OpenAI Responses (Daybreak): reasoning.effort; Chat Completions (OpenAI, Copilot, LM Studio): reasoning_effort
 */
const CLAUDE = ['low', 'medium', 'high', 'xhigh', 'max'];
const OPENAI = ['low', 'medium', 'high', 'xhigh'];
const BASIC = ['low', 'medium', 'high'];
const EFFORT_LEVELS = Object.freeze({
  claude: CLAUDE, bedrock: CLAUDE, 'claude-code': CLAUDE,
  openai: OPENAI, codex: OPENAI, daybreak: OPENAI, 'daybreak-bedrock': OPENAI,
  copilot: BASIC, lmstudio: BASIC,
});

/** Returns a valid effort for the provider, '' for the default, or null when the value is not accepted. */
function normalizeEffort(provider, value) {
  if (value === undefined || value === null || value === '') return '';
  if (typeof value !== 'string') return null;
  const effort = value.trim().toLowerCase();
  if (!effort) return '';
  return (EFFORT_LEVELS[provider] || []).includes(effort) ? effort : null;
}

module.exports = { EFFORT_LEVELS, normalizeEffort };
