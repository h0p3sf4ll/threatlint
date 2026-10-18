'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DATA_DIR = process.env.THREATLINT_DATA_DIR || path.resolve(__dirname, '../../src/threatlint/data');
const SKILL_MAP = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'agent-skills.json'), 'utf8'));

function parseMarkdown(raw) {
  const match = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) throw new Error('Missing Markdown frontmatter');
  const meta = {};
  for (const line of match[1].split('\n')) {
    const colon = line.indexOf(':');
    if (colon > 0) meta[line.slice(0, colon).trim()] = line.slice(colon + 1).trim().replace(/^(["'])(.*)\1$/, '$2');
  }
  return { meta, body: match[2].trim() };
}

const ROLE_META = {
  'appsec-threat-modeler': ['Threat model', 'Analysis', 'TM', 'Map trust boundaries, crown jewels, and evidence-backed attack paths.', 'System model, prioritized threat register, proposed controls, and validation plan.'],
  'appsec-code-reviewer': ['Code review', 'Analysis', 'CR', 'Review a diff or pull request for security regressions and broken controls.', 'Evidence-backed findings, proposed patches, and a scoped merge recommendation.'],
  'appsec-dependency-auditor': ['Dependencies', 'Supply Chain', 'DA', 'Trace resolved packages, advisory applicability, and supply-chain trust.', 'Dependency risk inventory and a compatible, prioritized upgrade plan.'],
  'appsec-secrets-scanner': ['Secrets scan', 'Exposure', 'SS', 'Find credential exposure without revealing or testing sensitive values.', 'Redacted evidence, exposure assessment, and a sequenced rotation plan.'],
  'appsec-iac-reviewer': ['Infrastructure', 'Infrastructure', 'IC', 'Review cloud identity, network exposure, containers, and secure defaults.', 'Resource-specific findings, configuration proposals, and rollout checks.'],
  'appsec-cicd-auditor': ['CI/CD audit', 'Supply Chain', 'CI', 'Follow event, runner, token, artifact, and deployment trust boundaries.', 'Pipeline findings, least-privilege YAML proposals, and release safeguards.'],
  'appsec-api-security-reviewer': ['API security', 'Analysis', 'AR', 'Trace endpoint authorization, tenant isolation, resource limits, and data exposure.', 'Endpoint-level findings, contract-aware fixes, and role/tenant regression tests.'],
  'appsec-auth-reviewer': ['Authentication', 'Analysis', 'AU', 'Examine identity lifecycles, sessions, tokens, recovery, and authorization.', 'Identity-boundary findings and framework-specific remediation guidance.'],
  'appsec-fp-reviewer': ['Findings triage', 'Analysis', 'FP', 'Turn scanner noise into defensible decisions and implementation-ready fixes.', 'Executive findings report, proposed fixes, safe rule tuning, and acceptance matrix.'],
  'appsec-compliance-checker': ['Compliance map', 'Compliance', 'CC', 'Map verified findings to applicable controls without certification claims.', 'Traceable control-gap matrix, closure evidence, and remediation roadmap.'],
  'appsec-attack-tree': ['Attack tree', 'Adversarial', 'AT', 'Model AND/OR paths, verified defenses, prerequisites, and defensive cuts.', 'Mermaid attack tree, ranked leaves, and bounded defensive validation plans.'],
  'appsec-red-team': ['Adversarial scenarios', 'Adversarial', 'RT', 'Develop evidence-grounded scenarios and safe purple-team validation plans.', 'Bounded kill chains, detection hypotheses, and prevention recommendations.'],
  'appsec-threat-delta': ['Threat delta', 'Analysis', 'TD', 'Compare prior findings to current code and highlight new or regressed risk.', 'Original-ID traceability, closure verdicts, and updated remediation priorities.'],
  'appsec-verify-fix': ['Verify a fix', 'Analysis', 'VF', 'Verify root-cause remediation and search for equivalent bypasses.', 'Qualified fix verdict, current evidence, residual risk, and acceptance checks.'],
  'appsec-runtime-reviewer': ['Runtime review', 'Analysis', 'DX', 'Correlate supplied, authorized runtime captures with source and authentication state.', 'Source/capture evidence matrix, qualified findings, and NOT RUN validation proposals.'],
  'appsec-business-logic-reviewer': ['Business logic', 'Analysis', 'BL', 'Trace workflow invariants, entitlements, idempotency, races, and asynchronous side effects.', 'Invariant-specific findings, advisory fixes, and synthetic acceptance cases.'],
  'appsec-client-security-reviewer': ['Client security', 'Analysis', 'CL', 'Review browser, Electron, and mobile rendering, origins, storage, and privileged bridges.', 'Client-boundary findings, framework-native fixes, and isolation acceptance criteria.'],
  'appsec-crypto-reviewer': ['Cryptography', 'Analysis', 'CY', 'Review security purpose, primitives, key/nonce lifecycles, and TLS verification.', 'Evidence-backed cryptographic findings and compatibility-aware migration proposals.'],
  'appsec-ai-security-reviewer': ['AI/LLM security', 'Analysis', 'AI', 'Trace prompt injection, retrieval, memory, tools, outputs, and tenant authority boundaries.', 'AI trust-boundary findings, deterministic control proposals, and synthetic acceptance cases.'],
  'appsec-security-test-planner': ['Security test plan', 'Analysis', 'ST', 'Plan evidence-grounded regression coverage, role/tenant cases, and manual SSO/MFA prerequisites.', 'Traceable acceptance plan with owners, authorization blockers, and NOT RUN test cases.'],
  'appsec-secure-codegen-reviewer': ['Secure codegen', 'Analysis', 'SG', 'Catch insecure defaults in AI-generated or new code and propose secure-by-default rewrites.', 'Source-to-sink findings, before/after secure rewrites, and reusable IDE/assistant guardrails.'],
  'appsec-privacy-reviewer': ['Privacy & data', 'Analysis', 'PD', 'Inventory personal data and trace it to logs, analytics, AI providers, and third parties.', 'Data inventory, flow-specific findings, minimization/retention fixes, and synthetic-data acceptance cases.'],
};

function loadSkills() {
  const skills = {};
  for (const id of new Set(Object.values(SKILL_MAP).flat())) {
    if (!/^threatlint-[a-z0-9-]+$/.test(id)) throw new Error(`Invalid skill: ${id}`);
    const { meta, body } = parseMarkdown(fs.readFileSync(path.join(DATA_DIR, 'skills', id, 'SKILL.md'), 'utf8'));
    if (meta.name !== id || !meta.description || !body) throw new Error(`Invalid skill definition: ${id}`);
    skills[id] = { id, name: id.replace('threatlint-', '').replaceAll('-', ' '), description: meta.description, body,
      agents: Object.keys(SKILL_MAP).filter(agent => SKILL_MAP[agent].includes(id)) };
  }
  return skills;
}

const SKILLS = loadSkills();

function loadAgents() {
  return Object.fromEntries(Object.entries(SKILL_MAP).map(([id, skillIds]) => {
    const { meta, body } = parseMarkdown(fs.readFileSync(path.join(DATA_DIR, 'agents', `${id}.md`), 'utf8'));
    const [label, category, initials, description, deliverable] = ROLE_META[id];
    const skills = skillIds.map(skillId => SKILLS[skillId]);
    const workflows = skills.map(skill => `### Required skill: ${skill.id}\n\n${skill.body}`).join('\n\n');
    return [id, { id, name: meta.name || id, label, category, initials, description, deliverable,
      color: category === 'Adversarial' ? '#f39591' : '#77dcc0', emoji: initials, skills,
      inputHint: id === 'appsec-fp-reviewer' ? 'Attach SARIF, Semgrep JSON, or a prior findings report.' : 'Optional component, path, comparison range, or review objective.',
      systemPrompt: `${body}\n\n## Required Skill Workflows\n\n${workflows}\n\nThese evidence and reporting workflows govern this analysis. Proposals are advisory; no changes may be applied.`,
    }];
  }));
}

const AGENTS = loadAgents();

function publicAgent(agent) {
  const { systemPrompt, skills, ...fields } = agent;
  return { ...fields, skills: skills.map(({ id, name, description }) => ({ id, name, description })) };
}

module.exports = { AGENTS, SKILLS, DATA_DIR, SKILL_MAP, parseMarkdown, loadAgents, publicAgent };