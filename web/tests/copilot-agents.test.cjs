'use strict';
/**
 * GitHub Copilot Chat agent file tests — verifies every .github/agents/*.agent.md
 * has valid frontmatter and substantive content.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const COPILOT_AGENTS_DIR = path.resolve(__dirname, '../../.github/agents');

const EXPECTED_COPILOT_AGENTS = [
  'appsec-threat-modeler',
  'appsec-code-reviewer',
  'appsec-dependency-auditor',
  'appsec-secrets-scanner',
  'appsec-iac-reviewer',
  'appsec-cicd-auditor',
  'appsec-api-security-reviewer',
  'appsec-auth-reviewer',
  'appsec-fp-reviewer',
  'appsec-compliance-checker',
  'appsec-attack-tree',
  'appsec-red-team',
  'appsec-threat-delta',
  'appsec-verify-fix',
];

function loadCopilotAgents() {
  const agents = {};
  const files = fs.readdirSync(COPILOT_AGENTS_DIR).filter(f => f.endsWith('.agent.md'));
  for (const file of files) {
    const raw = fs.readFileSync(path.join(COPILOT_AGENTS_DIR, file), 'utf8');
    const fm = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
    if (!fm) continue;
    const meta = {};
    fm[1].split('\n').forEach(line => {
      const c = line.indexOf(':');
      if (c > 0) meta[line.slice(0, c).trim()] = line.slice(c + 1).trim().replace(/^"|"$/g, '');
    });
    const id = path.basename(file, '.agent.md');
    agents[id] = { id, meta, body: fm[2].trim(), raw };
  }
  return agents;
}

const agents = loadCopilotAgents();

describe('Copilot Chat agent directory', () => {
  it('directory exists', () => {
    assert.ok(fs.existsSync(COPILOT_AGENTS_DIR), `Directory not found: ${COPILOT_AGENTS_DIR}`);
  });

  it('contains all 14 agent files', () => {
    const missing = EXPECTED_COPILOT_AGENTS.filter(id => !agents[id]);
    assert.deepEqual(missing, [], `Missing .github/agents files: ${missing.join(', ')}`);
  });
});

describe('Copilot Chat agent frontmatter', () => {
  for (const id of EXPECTED_COPILOT_AGENTS) {
    it(`${id}: has name field`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      assert.ok(a.meta.name && a.meta.name.length > 3, `${id}: missing or short name`);
    });

    it(`${id}: has description field`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      assert.ok(a.meta.description && a.meta.description.length > 20, `${id}: missing or short description`);
    });

    it(`${id}: has tools field`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      // Support both single-line (tools: [read, search]) and multi-line (tools:\n  - read) YAML
      assert.ok(a.raw.match(/^tools[\s\S]/m), `${id}: missing tools`);
    });

    it(`${id}: body is substantial (>200 chars)`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      assert.ok(a.body.length > 200, `${id}: body too short (${a.body.length} chars)`);
    });

    it(`${id}: does not instruct file mutation`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      assert.ok(!a.body.includes('fs.writeFile'), `${id}: contains writeFile`);
      assert.ok(!a.body.includes('git commit'), `${id}: contains git commit`);
    });
  }
});

describe('Copilot Chat agent content integrity', () => {
  it('compliance-checker references all 7 frameworks', () => {
    const a = agents['appsec-compliance-checker'];
    assert.ok(a, 'compliance-checker not loaded');
    for (const fw of ['ASVS', 'PCI-DSS', 'HIPAA', 'SOC 2', 'ISO 27001', 'NIST CSF', 'CIS']) {
      assert.ok(a.body.includes(fw), `compliance-checker .agent.md missing: ${fw}`);
    }
  });

  it('attack-tree has AND, OR, LEAF node instructions', () => {
    const a = agents['appsec-attack-tree'];
    assert.ok(a, 'attack-tree not loaded');
    assert.ok(a.body.includes('AND'));
    assert.ok(a.body.includes('OR'));
    assert.ok(a.body.includes('LEAF'));
  });

  it('red-team requires 5 scenarios and kill chains', () => {
    const a = agents['appsec-red-team'];
    assert.ok(a, 'red-team not loaded');
    assert.ok(a.body.includes('5'));
    assert.ok(a.body.toLowerCase().includes('kill chain'));
  });

  it('threat-delta defines all verdict types', () => {
    const a = agents['appsec-threat-delta'];
    assert.ok(a, 'threat-delta not loaded');
    for (const v of ['RESOLVED', 'PARTIALLY FIXED', 'STILL PRESENT', 'REGRESSED', 'NEW']) {
      assert.ok(a.body.includes(v), `threat-delta .agent.md missing verdict: ${v}`);
    }
  });

  it('verify-fix defines all 4 verdict types', () => {
    const a = agents['appsec-verify-fix'];
    assert.ok(a, 'verify-fix not loaded');
    for (const v of ['REMEDIATED', 'PARTIALLY FIXED', 'STILL PRESENT', 'REGRESSED']) {
      assert.ok(a.body.includes(v), `verify-fix .agent.md missing verdict: ${v}`);
    }
  });
});
