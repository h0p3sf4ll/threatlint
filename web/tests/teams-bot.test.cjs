'use strict';
/**
 * Teams bot tests — verifies command routing table, bot file integrity,
 * and manifest.json structure.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const SKILL_MAP = require('../../src/threatlint/data/agent-skills.json');

const TEAMS_APP_DIR = path.resolve(__dirname, '../../teams-app');
const BOT_FILE = path.join(TEAMS_APP_DIR, 'bot.js');
const MANIFEST_FILE = path.join(TEAMS_APP_DIR, 'manifest.json');

const EXPECTED_ROUTES = {
  'threat-model': 'appsec-threat-modeler', 'security-review': 'appsec-code-reviewer',
  'dependency-audit': 'appsec-dependency-auditor', 'secrets-scan': 'appsec-secrets-scanner',
  'iac-review': 'appsec-iac-reviewer', 'cicd-audit': 'appsec-cicd-auditor',
  'api-security-review': 'appsec-api-security-reviewer', 'auth-review': 'appsec-auth-reviewer',
  'fp-review': 'appsec-fp-reviewer', 'compliance-check': 'appsec-compliance-checker',
  'attack-tree': 'appsec-attack-tree', 'red-team': 'appsec-red-team',
  'threat-delta': 'appsec-threat-delta', 'verify-fix': 'appsec-verify-fix',
  'runtime-review': 'appsec-runtime-reviewer', 'business-logic-review': 'appsec-business-logic-reviewer',
  'client-security-review': 'appsec-client-security-reviewer', 'crypto-review': 'appsec-crypto-reviewer',
  'ai-security-review': 'appsec-ai-security-reviewer', 'security-test-plan': 'appsec-security-test-planner',
  'secure-codegen-review': 'appsec-secure-codegen-reviewer', 'privacy-review': 'appsec-privacy-reviewer',
};
const EXPECTED_COMMANDS = Object.keys(EXPECTED_ROUTES);
const botSrc = fs.readFileSync(BOT_FILE, 'utf8');
const routeBody = botSrc.match(/const COMMAND_TO_AGENT = \{([\s\S]*?)\n\};/)[1];
const routes = Object.fromEntries([...routeBody.matchAll(/'([^']+)':\s*'([^']+)'/g)].map(match => [match[1], match[2]]));

describe('Teams bot file structure', () => {
  it('teams-app/ directory exists', () => {
    assert.ok(fs.existsSync(TEAMS_APP_DIR), `Directory not found: ${TEAMS_APP_DIR}`);
  });

  it('bot.js exists', () => {
    assert.ok(fs.existsSync(BOT_FILE), 'bot.js not found');
  });

  it('manifest.json exists', () => {
    assert.ok(fs.existsSync(MANIFEST_FILE), 'manifest.json not found');
  });

  it('package.json exists and has start script', () => {
    const pkgPath = path.join(TEAMS_APP_DIR, 'package.json');
    assert.ok(fs.existsSync(pkgPath), 'teams-app/package.json not found');
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    assert.ok(pkg.scripts?.start, 'package.json missing start script');
  });
});

describe('Teams bot command routing', () => {
  it('preserves existing commands and routes each specialist to its own agent', () => {
    assert.deepEqual(routes, EXPECTED_ROUTES);
  });

  it('routes to every registered agent with its ordered skill bodies', () => {
    assert.deepEqual([...new Set(Object.values(routes))].sort(), Object.keys(SKILL_MAP).sort());
    // Evaluate only the prompt loader; do not import the bot, create a listener, or call a provider.
    const loader = botSrc.match(/function loadAgentPrompt\(agentId\) \{[\s\S]*?\n\}/)[0];
    const DATA_DIR = path.resolve(TEAMS_APP_DIR, '../src/threatlint/data');
    const loadPrompt = vm.runInNewContext(`(${loader})`, { fs, path, DATA_DIR, AGENTS_DIR: path.join(DATA_DIR, 'agents') });
    for (const id of Object.keys(SKILL_MAP)) {
      const prompt = loadPrompt(id);
      let previous = -1;
      for (const skill of SKILL_MAP[id]) {
        const body = fs.readFileSync(path.join(DATA_DIR, 'skills', skill, 'SKILL.md'), 'utf8').replace(/^---\n[\s\S]*?\n---\n/, '').trim();
        const position = prompt.indexOf(body);
        assert.ok(position > previous, `${id}: missing or out-of-order ${skill}`);
        previous = position;
      }
      assert.match(prompt, /no repository inspection tools/);
      assert.match(prompt, /No runtime or browser tools/);
      assert.match(prompt, /NOT RUN/);
    }
  });

  it('bot has require.main === module guard (does not auto-start on import)', () => {
    assert.ok(botSrc.includes('require.main === module'), 'bot.js missing require.main guard');
  });

  it('bot exports { bot, server, adapter }', () => {
    assert.ok(botSrc.includes('module.exports'), 'bot.js missing module.exports');
    assert.ok(botSrc.includes('server'), 'bot.js exports missing server');
  });

  it('bot uses Anthropic SDK for completions', () => {
    assert.ok(botSrc.includes('@anthropic-ai/sdk'), 'bot.js does not use @anthropic-ai/sdk');
  });
});

describe('Teams app manifest', () => {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf8'));

  it('manifest has required fields', () => {
    assert.ok(manifest.manifestVersion, 'manifest missing manifestVersion');
    assert.ok(manifest.id, 'manifest missing id');
    assert.ok(manifest.name?.short, 'manifest missing name.short');
    assert.ok(manifest.bots?.length > 0, 'manifest missing bots array');
  });

  it('manifest bot matches routing entries plus help without duplicate commands', () => {
    const commands = manifest.bots?.[0]?.commandLists?.[0]?.commands || [];
    const titles = commands.map(c => c.title);
    assert.deepEqual([...titles].sort(), [...EXPECTED_COMMANDS, 'help'].sort());
    assert.equal(new Set(titles).size, titles.length);
    assert.ok(commands.every(command => command.description.length > 10 && command.description.length <= 80));
    assert.match(manifest.description.full, /supplied redacted evidence only/);
    assert.match(manifest.description.full, /cannot inspect repositories/);
  });

  it('manifest scopes include personal, team, groupchat', () => {
    const scopes = manifest.bots?.[0]?.commandLists?.[0]?.scopes || [];
    assert.ok(scopes.includes('personal'), 'manifest missing personal scope');
    assert.ok(scopes.includes('team'), 'manifest missing team scope');
    assert.ok(scopes.includes('groupchat'), 'manifest missing groupchat scope');
  });
});
