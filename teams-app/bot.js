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
 *   CLAUDE_MODEL        — model to use (default claude-sonnet-5)
 */

const path = require('node:path');
const fs = require('node:fs');
const restify = require('restify');
const { BotFrameworkAdapter, TurnContext, ActivityHandler } = require('botbuilder');
const Anthropic = require('@anthropic-ai/sdk');

const PORT = parseInt(process.env.PORT || '3978', 10);
const MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';
const AGENTS_DIR = path.resolve(__dirname, '../.claude/agents');

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
};

function loadAgentPrompt(agentId) {
  const agentPath = path.join(AGENTS_DIR, `${agentId}.md`);
  if (!fs.existsSync(agentPath)) return null;
  const raw = fs.readFileSync(agentPath, 'utf8');
  const match = raw.match(/^---\n[\s\S]*?\n---\n([\s\S]*)$/);
  return match ? match[1].trim() : raw.trim();
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
  return `**threatlint — AppSec Agents**\n\nAvailable commands:\n${rows}\n\nUsage: \`/threat-model [target]\` or \`@threatlint threat-model [target]\`\n\nAll agents are read-only. No files are modified.`;
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

      await context.sendActivity(`Running **${agentId}**${args ? ` on \`${args}\`` : ''}…`);

      const userMessage = args
        ? `Analyze the following target: ${args}`
        : 'Perform a complete analysis. Discover the repository scope automatically.';

      try {
        const stream = await anthropic.messages.stream({
          model: MODEL,
          max_tokens: 8192,
          system: systemPrompt,
          messages: [{ role: 'user', content: userMessage }],
        });

        let report = '';
        for await (const event of stream) {
          if (event.type === 'content_block_delta' && event.delta?.type === 'text_delta') {
            report += event.delta.text;
          }
        }

        // Teams message size limit: ~28 KB per activity. Split large reports.
        const CHUNK = 25000;
        if (report.length <= CHUNK) {
          await context.sendActivity(report);
        } else {
          for (let i = 0; i < report.length; i += CHUNK) {
            await context.sendActivity(report.slice(i, i + CHUNK));
          }
        }
      } catch (err) {
        console.error('[threatlint] API error:', err);
        await context.sendActivity(`Analysis failed: ${err.message || String(err)}`);
      }

      await next();
    });

    this.onMembersAdded(async (context, next) => {
      for (const member of context.activity.membersAdded || []) {
        if (member.id !== context.activity.recipient.id) {
          await context.sendActivity(
            'Welcome to **threatlint**! I run application security agents powered by Claude AI.\n\nType `/help` to see all available commands.'
          );
        }
      }
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
