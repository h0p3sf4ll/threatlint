'use strict';
/**
 * Teams bot tests — verifies command routing table, bot file integrity,
 * and manifest.json structure.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const TEAMS_APP_DIR = path.resolve(__dirname, '../../teams-app');
const BOT_FILE = path.join(TEAMS_APP_DIR, 'bot.js');
const MANIFEST_FILE = path.join(TEAMS_APP_DIR, 'manifest.json');

const EXPECTED_COMMANDS = [
  'threat-model', 'security-review', 'dependency-audit', 'secrets-scan',
  'iac-review', 'cicd-audit', 'api-security-review', 'auth-review',
  'fp-review', 'compliance-check', 'attack-tree', 'red-team',
  'threat-delta', 'verify-fix',
];

const EXPECTED_AGENTS = [
  'appsec-threat-modeler', 'appsec-code-reviewer', 'appsec-dependency-auditor',
  'appsec-secrets-scanner', 'appsec-iac-reviewer', 'appsec-cicd-auditor',
  'appsec-api-security-reviewer', 'appsec-auth-reviewer', 'appsec-fp-reviewer',
  'appsec-compliance-checker', 'appsec-attack-tree', 'appsec-red-team',
  'appsec-threat-delta', 'appsec-verify-fix',
];

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
  const botSrc = fs.readFileSync(BOT_FILE, 'utf8');

  it('COMMAND_TO_AGENT contains all 14 commands', () => {
    for (const cmd of EXPECTED_COMMANDS) {
      assert.ok(botSrc.includes(`'${cmd}'`), `bot.js missing command: ${cmd}`);
    }
  });

  it('COMMAND_TO_AGENT maps to all 14 agents', () => {
    for (const agent of EXPECTED_AGENTS) {
      assert.ok(botSrc.includes(`'${agent}'`), `bot.js missing agent: ${agent}`);
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

  it('manifest bot has all 14 command entries + help', () => {
    const commands = manifest.bots?.[0]?.commandLists?.[0]?.commands || [];
    const titles = commands.map(c => c.title);
    for (const cmd of EXPECTED_COMMANDS) {
      assert.ok(titles.includes(cmd), `manifest missing command: ${cmd}`);
    }
    assert.ok(titles.includes('help'), 'manifest missing help command');
  });

  it('manifest scopes include personal, team, groupchat', () => {
    const scopes = manifest.bots?.[0]?.commandLists?.[0]?.scopes || [];
    assert.ok(scopes.includes('personal'), 'manifest missing personal scope');
    assert.ok(scopes.includes('team'), 'manifest missing team scope');
    assert.ok(scopes.includes('groupchat'), 'manifest missing groupchat scope');
  });
});
