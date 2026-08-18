'use strict';
/**
 * Agent registry tests — verifies every .md file loads correctly and is
 * registered in AGENT_META with the required fields.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const AGENTS_DIR = path.resolve(__dirname, '../../.claude/agents');

function loadAgents() {
  const agents = {};
  for (const file of fs.readdirSync(AGENTS_DIR).filter(f => f.endsWith('.md'))) {
    const raw = fs.readFileSync(path.join(AGENTS_DIR, file), 'utf8');
    const fm = raw.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
    if (!fm) continue;
    const meta = {};
    fm[1].split('\n').forEach(line => {
      const c = line.indexOf(':');
      if (c > 0) meta[line.slice(0, c).trim()] = line.slice(c + 1).trim();
    });
    const id = path.basename(file, '.md');
    agents[id] = {
      id,
      name: meta.name || id,
      description: (meta.description || '').replace(/^"|"$/g, ''),
      tools: meta.tools || '',
      disallowedTools: meta.disallowedTools || '',
      systemPrompt: fm[2].trim(),
    };
  }
  return agents;
}

const AGENT_META = {
  'appsec-threat-modeler':        { label: 'Threat Model',    color: '#ff6b6b', emoji: '🎯', category: 'Analysis' },
  'appsec-code-reviewer':         { label: 'Code Review',     color: '#ffd93d', emoji: '🔍', category: 'Analysis' },
  'appsec-dependency-auditor':    { label: 'Dependencies',    color: '#6bcb77', emoji: '📦', category: 'Supply Chain' },
  'appsec-secrets-scanner':       { label: 'Secrets Scan',    color: '#4d96ff', emoji: '🔑', category: 'Exposure' },
  'appsec-iac-reviewer':          { label: 'IaC Review',      color: '#c77dff', emoji: '☁️', category: 'Infrastructure' },
  'appsec-cicd-auditor':          { label: 'CI/CD Audit',     color: '#ff9671', emoji: '⚙️', category: 'Supply Chain' },
  'appsec-api-security-reviewer': { label: 'API Security',    color: '#00c9a7', emoji: '🌐', category: 'Analysis' },
  'appsec-auth-reviewer':         { label: 'Auth Review',     color: '#f9c74f', emoji: '🛡️', category: 'Analysis' },
  'appsec-fp-reviewer':           { label: 'FP Triage',       color: '#90e0ef', emoji: '⚖️', category: 'Analysis' },
  'appsec-compliance-checker':    { label: 'Compliance Map',  color: '#a8dadc', emoji: '📋', category: 'Compliance' },
  'appsec-attack-tree':           { label: 'Attack Tree',     color: '#e63946', emoji: '🌳', category: 'Adversarial' },
  'appsec-red-team':              { label: 'Red Team',        color: '#d62828', emoji: '⚔️', category: 'Adversarial' },
  'appsec-threat-delta':          { label: 'Threat Delta',    color: '#b5838d', emoji: '📊', category: 'Analysis' },
  'appsec-verify-fix':            { label: 'Verify Fix',      color: '#52b788', emoji: '✅', category: 'Analysis' },
};

const EXPECTED = Object.keys(AGENT_META);
const agents = loadAgents();

describe('Agent file loading', () => {
  it('agents directory exists', () => {
    assert.ok(fs.existsSync(AGENTS_DIR));
  });

  it('loads all 14 expected agents', () => {
    const missing = EXPECTED.filter(id => !agents[id]);
    assert.deepEqual(missing, [], `Missing agent files: ${missing.join(', ')}`);
  });

  it('no agent is missing frontmatter delimiters', () => {
    for (const file of fs.readdirSync(AGENTS_DIR).filter(f => f.endsWith('.md'))) {
      const raw = fs.readFileSync(path.join(AGENTS_DIR, file), 'utf8');
      assert.ok(raw.startsWith('---\n'), `${file}: missing opening ---`);
      assert.ok(raw.includes('\n---\n'), `${file}: missing closing ---`);
    }
  });
});

describe('Agent field validation', () => {
  for (const id of EXPECTED) {
    it(`${id}: loads with required fields`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      assert.ok(a.name, `${id}: missing name`);
      assert.ok(a.description.length > 20, `${id}: description too short`);
      assert.ok(a.systemPrompt.length > 100, `${id}: system prompt too short`);
    });

    it(`${id}: disallows Write and Edit`, () => {
      const a = agents[id];
      assert.ok(a, `Not loaded: ${id}`);
      const disallowed = a.disallowedTools.split(',').map(s => s.trim());
      assert.ok(disallowed.includes('Write'), `${id}: Write not disallowed`);
      assert.ok(disallowed.includes('Edit'), `${id}: Edit not disallowed`);
    });

    it(`${id}: AGENT_META has label, color, emoji, category`, () => {
      const m = AGENT_META[id];
      assert.ok(m.label && m.color && m.emoji && m.category);
      assert.match(m.color, /^#[0-9a-f]{6}$/i, `${id}: color not valid hex`);
    });
  }
});

describe('Agent content integrity', () => {
  it('compliance-checker references all 7 frameworks', () => {
    const sp = agents['appsec-compliance-checker']?.systemPrompt || '';
    for (const fw of ['ASVS', 'PCI-DSS', 'HIPAA', 'SOC 2', 'ISO 27001', 'NIST CSF', 'CIS']) {
      assert.ok(sp.includes(fw), `compliance-checker missing: ${fw}`);
    }
  });

  it('attack-tree has AND, OR, LEAF node instructions', () => {
    const sp = agents['appsec-attack-tree']?.systemPrompt || '';
    assert.ok(sp.includes('AND'));
    assert.ok(sp.includes('OR'));
    assert.ok(sp.includes('LEAF'));
  });

  it('red-team requires 5 scenarios and kill chains', () => {
    const sp = agents['appsec-red-team']?.systemPrompt || '';
    assert.ok(sp.includes('5'));
    assert.ok(sp.toLowerCase().includes('kill chain'));
  });

  it('threat-delta defines all 5 verdict types', () => {
    const sp = agents['appsec-threat-delta']?.systemPrompt || '';
    for (const v of ['RESOLVED', 'PARTIALLY FIXED', 'STILL PRESENT', 'REGRESSED', 'NEW']) {
      assert.ok(sp.includes(v), `threat-delta missing verdict: ${v}`);
    }
  });

  it('verify-fix defines all 4 verdict types', () => {
    const sp = agents['appsec-verify-fix']?.systemPrompt || '';
    for (const v of ['REMEDIATED', 'PARTIALLY FIXED', 'STILL PRESENT', 'REGRESSED']) {
      assert.ok(sp.includes(v), `verify-fix missing verdict: ${v}`);
    }
  });

  it('no agent instructs file mutations', () => {
    for (const id of EXPECTED) {
      const sp = agents[id]?.systemPrompt || '';
      assert.ok(!sp.includes('fs.writeFile'), `${id}: contains writeFile`);
      assert.ok(!sp.includes('git commit'), `${id}: contains git commit`);
    }
  });
});

describe('AGENT_META completeness', () => {
  it('every loaded agent has an AGENT_META entry', () => {
    const loaded = Object.keys(agents);
    const missing = loaded.filter(id => !AGENT_META[id]);
    assert.deepEqual(missing, []);
  });

  it('every AGENT_META entry has a .md file', () => {
    const missing = EXPECTED.filter(id => !agents[id]);
    assert.deepEqual(missing, []);
  });
});
