'use strict';
/**
 * Agent registry tests — verifies every .md file loads correctly and is
 * registered in the canonical registry with the required product metadata.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { AGENTS: AGENT_META, SKILL_MAP } = require('../lib/agents.cjs');

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

const EXPECTED = Object.keys(SKILL_MAP);
const agents = loadAgents();

describe('Agent file loading', () => {
  it('agents directory exists', () => {
    assert.ok(fs.existsSync(AGENTS_DIR));
  });

  it('loads exactly the registered agents', () => {
    assert.deepEqual(Object.keys(agents).sort(), [...EXPECTED].sort());
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

    it(`${id}: declares only inspection tools`, () => {
      const allowed = new Set(['Read', 'Grep', 'Glob', 'Bash']);
      const tools = agents[id].tools.split(',').map(tool => tool.trim());
      assert.ok(tools.length > 0);
      assert.ok(tools.every(tool => allowed.has(tool)), `${id}: unexpected tool`);
    });

    it(`${id}: AGENT_META has label, color, emoji, category`, () => {
      const m = AGENT_META[id];
      assert.ok(m.label && m.color && m.emoji && m.category);
      assert.match(m.color, /^#[0-9a-f]{6}$/i, `${id}: color not valid hex`);
    });
  }
});

describe('Agent content integrity', () => {
  it('specialists expose their distinct finding prefixes and advisory deliverables', () => {
    const prefixes = {
      'appsec-runtime-reviewer': 'DX', 'appsec-business-logic-reviewer': 'BL',
      'appsec-client-security-reviewer': 'CL', 'appsec-crypto-reviewer': 'CY',
      'appsec-ai-security-reviewer': 'AI', 'appsec-security-test-planner': 'ST',
      'appsec-secure-codegen-reviewer': 'SG', 'appsec-privacy-reviewer': 'PD',
    };
    for (const [id, prefix] of Object.entries(prefixes)) {
      assert.equal(AGENT_META[id].initials, prefix);
      assert.ok(AGENT_META[id].deliverable.length > 30);
      assert.ok(agents[id].systemPrompt.includes(`[${prefix}-NNN]`));
      assert.match(agents[id].systemPrompt, /persistence is host-owned/);
      assert.match(agents[id].systemPrompt, /NOT RUN/);
    }
  });

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
