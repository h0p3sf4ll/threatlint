'use strict';
/**
 * threatlint Teams bot — routes security analysis commands to Claude AI agents
 * via the Anthropic API, then streams the report back into the Teams conversation.
 *
 * Environment variables required:
 *   ANTHROPIC_API_KEY   — Anthropic API key
 *   BOT_APP_ID          — Azure Bot App ID (from Azure Bot registration)
 *   BOT_APP_PASSWORD    — Azure Bot App Password
 *
 * Optional:
 *   PORT                — HTTP port (default 3978)
 *   CLAUDE_MODEL        — model to use (default: the Threatlint scanning model, claude-sonnet-5-5,
 *                         or THREATLINT_SCAN_MODEL / org.json scanModel; see web/lib/model-policy.cjs)
 */

const path = require('node:path');
const fs = require('node:fs');
const restify = require('restify');
const { BotFrameworkAdapter, TurnContext, ActivityHandler } = require('botbuilder');
const Anthropic = require('@anthropic-ai/sdk');
const { scanModel } = require('../web/lib/model-policy.cjs');

const PORT = Number.parseInt(process.env.PORT || '3978', 10);
// Every bot command runs a security analysis agent, so it follows the scanning model policy.
const MODEL = process.env.CLAUDE_MODEL || scanModel();
const DATA_DIR = path.resolve(__dirname, '../src/threatlint/data');
const AGENTS_DIR = path.join(DATA_DIR, 'agents');
const MAX_OUTPUT_TOKENS = 8192;
// Teams accepts roughly 28 KB per activity; leave headroom for formatting.
const TEAMS_MESSAGE_CHARS = 25000;

const WELCOME_TEXT = 'Welcome to **threatlint**! I run application security agents powered by Claude AI.\n\nType `/help` to see all available commands.';

/** Send activities strictly in order; Teams shows them in arrival order, so report chunks must not race. */
function sendInOrder(context, messages) {
  return messages.reduce((previous, message) => previous.then(() => context.sendActivity(message)), Promise.resolve());
}

/** Split text into Teams-sized chunks, preserving order. */
function chunks(text, size) {
  return Array.from({ length: Math.ceil(text.length / size) }, (_, index) => text.slice(index * size, (index + 1) * size));
}

const adapter = new BotFrameworkAdapter({
  appId: process.env.BOT_APP_ID || '',
  appPassword: process.env.BOT_APP_PASSWORD || '',
});

adapter.onTurnError = async (context, error) => {
  console.error('[threatlint] onTurnError:', error);
  await context.sendActivity('An error occurred processing your request. Check the bot logs.');
};

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ── Agent registry ─────────────────────────────────────────────────────────────

const COMMAND_TO_AGENT = {
  'threat-model':        'appsec-threat-modeler',
  'security-review':     'appsec-code-reviewer',
  'dependency-audit':    'appsec-dependency-auditor',
  'secrets-scan':        'appsec-secrets-scanner',
  'iac-review':          'appsec-iac-reviewer',
  'cicd-audit':          'appsec-cicd-auditor',
  'api-security-review': 'appsec-api-security-reviewer',
  'auth-review':         'appsec-auth-reviewer',
  'fp-review':           'appsec-fp-reviewer',
  'compliance-check':    'appsec-compliance-checker',
  'attack-tree':         'appsec-attack-tree',
  'red-team':            'appsec-red-team',
  'threat-delta':        'appsec-threat-delta',
  'verify-fix':          'appsec-verify-fix',
  'runtime-review':      'appsec-runtime-reviewer',
  'business-logic-review': 'appsec-business-logic-reviewer',
  'client-security-review': 'appsec-client-security-reviewer',
  'crypto-review':       'appsec-crypto-reviewer',
  'ai-security-review':  'appsec-ai-security-reviewer',
  'security-test-plan':  'appsec-security-test-planner',
  'secure-codegen-review': 'appsec-secure-codegen-reviewer',
  'privacy-review':      'appsec-privacy-reviewer',
};

function loadAgentPrompt(agentId) {
  const agentPath = path.join(AGENTS_DIR, `${agentId}.md`);
  if (!fs.existsSync(agentPath)) return null;
  const raw = fs.readFileSync(agentPath, 'utf8');
  const match = raw.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
  const body = match ? match[1].trim() : raw.trim();
  const registry = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'agent-skills.json'), 'utf8'));
  const skills = registry[agentId].map(id => {
    const source = fs.readFileSync(path.join(DATA_DIR, 'skills', id, 'SKILL.md'), 'utf8');
    return source.replace(/^---\n[\s\S]*?\n---\n/, '').trim();
  });
  return `${body}\n\n## Required Skill Workflows\n${skills.join('\n\n')}\n\nThis Teams runner has no repository inspection tools. Analyze only evidence explicitly supplied in the conversation. Do not claim a repository was inspected or findings verified when source is unavailable; identify the evidence needed or recommend the desktop/CLI runner. No runtime or browser tools are available: do not collect captures, send requests, log in, automate SSO/MFA, or execute tests. Missing source/auth/runtime evidence is a limitation, not a verified result; proposed validation is NOT RUN.`;
}

// ── Command parsing ────────────────────────────────────────────────────────────

function parseCommand(text) {
  const t = (text || '').trim().replace(/^@threatlint\s*/i, '');
  const parts = t.split(/\s+/);
  const cmd = parts[0].toLowerCase().replace(/^\//, '');
  const args = parts.slice(1).join(' ');
  return { cmd, args };
}

function helpText() {
  const rows = Object.keys(COMMAND_TO_AGENT).map(cmd => `• \`/${cmd}\``).join('\n');
  return `**threatlint — AppSec Agents**\n\nAvailable commands:\n${rows}\n\nUsage: \`/threat-model [target]\` or \`@threatlint threat-model [target]\`\n\nAll agents are read-only. No files are modified. Teams reviews supplied evidence only; it cannot inspect repositories, capture traffic, log in, or run tests. Supply redacted evidence without credentials or session tokens.`;
}

// ── Bot activity handler ───────────────────────────────────────────────────────

class ThreatLintBot extends ActivityHandler {
  constructor() {
    super();

    this.onMessage(async (context, next) => {
      const text = TurnContext.removeRecipientMention(context.activity) || context.activity.text || '';
      const { cmd, args } = parseCommand(text);

      if (!cmd || cmd === 'help') {
        await context.sendActivity(helpText());
        return next();
      }

      const agentId = COMMAND_TO_AGENT[cmd];
      if (!agentId) {
        await context.sendActivity(
          `Unknown command: \`/${cmd}\`. Type \`/help\` for the list of available commands.`
        );
        return next();
      }

      const systemPrompt = loadAgentPrompt(agentId);
      if (!systemPrompt) {
        await context.sendActivity(`Agent \`${agentId}\` not found. Ensure the threatlint agents are installed.`);
        return next();
      }

      const scope = args ? ` on \`${args}\`` : '';
      await context.sendActivity(`Running **${agentId}**${scope}…`);

      const userMessage = args
        ? `Analyze the following target: ${args}`
        : 'Perform a complete analysis. Discover the repository scope automatically.';

      try {
        const stream = await anthropic.messages.stream({
          model: MODEL,
          max_tokens: MAX_OUTPUT_TOKENS,
          system: systemPrompt,
          messages: [{ role: 'user', content: userMessage }],
        });

        let report = '';
        for await (const event of stream) {
          if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
            report += event.delta.text;
          }
        }

        await sendInOrder(context, report ? chunks(report, TEAMS_MESSAGE_CHARS) : ['The model returned an empty report.']);
      } catch (err) {
        console.error('[threatlint] API error:', err);
        await context.sendActivity(`Analysis failed: ${err.message || String(err)}`);
      }

      await next();
    });

    this.onMembersAdded(async (context, next) => {
      const newMembers = (context.activity.membersAdded || []).filter(member => member.id !== context.activity.recipient.id);
      await sendInOrder(context, newMembers.map(() => WELCOME_TEXT));
      await next();
    });
  }
}

// ── HTTP server ────────────────────────────────────────────────────────────────

const bot = new ThreatLintBot();
const server = restify.createServer({ name: 'threatlint-teams-bot' });
server.use(restify.plugins.bodyParser());

server.post('/api/messages', (req, res) => {
  adapter.processActivity(req, res, async context => {
    await bot.run(context);
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`threatlint Teams bot listening on port ${PORT}`);
    console.log(`POST http://localhost:${PORT}/api/messages`);
  });
}

module.exports = { bot, server, adapter };
