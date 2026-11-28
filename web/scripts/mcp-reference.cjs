'use strict';

// Discover the public protocol with inert services. Never start Workbench, open a
// user profile, invoke a tool, or contact a provider while generating documentation.
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { createMcpServer } = require('../lib/mcp.cjs');

const groups = [
  ['Specialist context', 'run-a-specialist-with-the-clients-model', ['list_agents', 'get_agent', 'list_skills']],
  ['Provider and setup discovery', 'install-and-connect-over-stdio', ['get_model_providers', 'list_models', 'get_setup_status']],
  ['Local workspace', 'first-scan-without-the-ui', ['list_workspaces', 'open_workspace', 'get_workspace', 'clone_repository']],
  ['Source accounts', 'sources-and-repository-checkout', ['list_source_providers', 'list_sources', 'connect_source', 'reconnect_source', 'disconnect_source', 'list_repositories', 'list_branches', 'checkout_repository']],
  ['Repository evidence', 'run-a-specialist-with-the-clients-model', ['read_file', 'find_files', 'search_files', 'inspect_git']],
  ['Source scans and fixes', 'first-scan-without-the-ui', ['start_scan', 'list_scans', 'get_scan', 'cancel_scan', 'propose_fix', 'apply_fix']],
  ['detect-2shell fleet scans', 'sources-and-repository-checkout', ['start_2shell_scan', 'list_2shell_scans', 'get_2shell_scan', 'cancel_2shell_scan']],
  ['Specialist jobs', 'background-reviews-and-conversations', ['start_review', 'list_reviews', 'get_review', 'cancel_review']],
  ['Conversations', 'background-reviews-and-conversations', ['ask_question', 'list_conversations', 'get_conversation']],
  ['Design inputs', 'background-reviews-and-conversations', ['upload_design_inputs', 'remove_design_inputs']],
  ['Imports and triage', 'imports-tracker-triage-and-runtime-scans', ['import_scan_report', 'list_imports', 'get_import', 'start_scanner_review', 'triage_tickets', 'post_import_review', 'post_scanner_review']],
  ['ServiceNow batch with write-back', 'imports-tracker-triage-and-runtime-scans', ['start_avit_review', 'get_avit_review', 'cancel_avit_review']],
  ['Runtime', 'runtime-request-configuration', ['start_runtime_scan', 'list_runtime_scans', 'get_runtime_scan', 'cancel_runtime_scan', 'export_runtime_scan', 'start_browser_signin', 'finish_browser_signin']],
  ['Findings', 'findings-and-decisions', ['list_findings', 'get_finding', 'ingest_findings', 'sync_reports', 'review_finding', 'resolve_findings', 'correlate_findings', 'get_composite']],
  ['Offline previews', 'findings-and-decisions', ['preview_composite_servicenow', 'preview_developer_risk']],
  ['Reports', 'reports-resources-and-prompts', ['list_reports', 'get_report', 'save_report', 'export_report', 'delete_report']],
];

async function discover() {
  const services = Object.fromEntries(['intelligence', 'reports', 'workspaces', 'reviews', 'sources', 'securityScanner', 'scanImports', 'designInputs', 'runtime', 'history', 'conversations', 'scannerBatch', 'avitRuns', 'twoShellFleet'].map(name => [name, Object.freeze({})]));
  const server = createMcpServer({ ...services, store: { sessions: new Map() } });
  const client = new Client({ name: 'threatlint-docs', version: '1.0.0' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const tools = [];
    let cursor;
    do {
      const page = await client.listTools(cursor ? { cursor } : undefined);
      tools.push(...page.tools);
      cursor = page.nextCursor;
    } while (cursor);
    return tools;
  } finally {
    await client.close();
    await server.close();
  }
}

const inline = value => '`' + String(value).replaceAll('`', '&#96;').replaceAll('|', '&#124;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('\n', ' ') + '`';
const cell = value => String(value).replaceAll('|', '&#124;').replaceAll('\n', ' ');
function type(schema) {
  if (schema.anyOf || schema.oneOf) return (schema.anyOf || schema.oneOf).map(type).join(' or ');
  if (schema.type === 'array') return `array of ${type(schema.items || {})}`;
  if (Array.isArray(schema.type)) return schema.type.join(' or ');
  return schema.type || 'any JSON value';
}
function constraints(schema) {
  const parts = [];
  if (Object.hasOwn(schema, 'const')) parts.push(`Must be ${inline(JSON.stringify(schema.const))}`);
  if (schema.enum) parts.push(schema.enum.length > 10 ? `${schema.enum.length} allowed values; see full schema` : `Allowed: ${schema.enum.map(value => inline(JSON.stringify(value))).join(', ')}`);
  if (Object.hasOwn(schema, 'default')) parts.push(`Default: ${inline(JSON.stringify(schema.default))}`);
  for (const [key, label] of [['minLength', 'Min length'], ['maxLength', 'Max length'], ['minimum', 'Minimum'], ['maximum', 'Maximum'], ['exclusiveMinimum', 'Greater than'], ['exclusiveMaximum', 'Less than'], ['minItems', 'Min items'], ['maxItems', 'Max items']]) {
    if (Object.hasOwn(schema, key)) parts.push(`${label}: ${schema[key]}`);
  }
  if (schema.format) parts.push(`Format: ${inline(schema.format)}`);
  if (schema.pattern) parts.push(`Pattern: ${inline(schema.pattern)}`);
  if (schema.description) parts.push(cell(schema.description));
  if (schema.properties || schema.items || schema.anyOf || schema.oneOf || typeof schema.additionalProperties === 'object') parts.push('Nested constraints: see full schema');
  return parts.join('; ') || '—';
}

function render(tools) {
  const byName = new Map(tools.map(tool => [tool.name, tool]));
  const grouped = groups.flatMap(([, , names]) => names);
  if (byName.size !== tools.length || new Set(grouped).size !== grouped.length || grouped.length !== tools.length || grouped.some(name => !byName.has(name))) {
    const missing = tools.map(tool => tool.name).filter(name => !grouped.includes(name));
    const stale = grouped.filter(name => !byName.has(name));
    throw new Error(`Update MCP reference groups to match tools/list. Ungrouped: ${missing.join(', ')}. Unregistered: ${stale.join(', ')}`);
  }
  const lines = [
    '---',
    'title: "MCP tool reference"',
    'description: "Every Threatlint MCP tool, with required arguments, defaults, limits, confirmation requirements, and complete input schemas."',
    'toc_max_heading_level: 3',
    '---', '',
    '<!-- Generated by web/scripts/mcp-reference.cjs from tools/list. Do not edit by hand. -->', '',
    '# MCP tool reference', '',
    `The full Threatlint server exposes **${tools.length} tools** over stdio and Streamable HTTP.`,
    'This reference is generated from the same `tools/list` response clients receive. Custom',
    'embedders may expose fewer tools when they omit backing services; discover the connected',
    'server before calling a tool.', '',
    'Start with [MCP and headless workflows](mcp.md) for installation, authentication, runnable',
    'examples, resources, prompts, and job lifecycles. Paths and interactive browsers refer to',
    'the server host. Use IDs returned by discovery/start calls in subsequent requests.', '',
    '## Calling tools and reading results', '',
    'Supply the listed arguments to MCP `tools/call`. For example:', '',
    '```json',
    '{"name":"open_workspace","arguments":{"repoPath":"/absolute/path/to/repository","confirm":true}}',
    '```', '',
    'Every successful call returns JSON text in `content` and the same decoded value in',
    '`structuredContent.result`. The common output schema declares an unconstrained',
    '`result` property whose shape depends on the tool; the schema does not promise a fixed',
    'structure for that value. Check `isError` before reading it. Tool failures contain an',
    'error message in text content; also handle protocol and transport errors in your client.', '',
    'A successful start call acknowledges a job. Poll its status, inspect coverage and errors,',
    'and retrieve the final report before treating the workflow as complete. Follow each',
    'workflow guide for response IDs, pagination cursors, cancellation, and retention.', '',
    'Required fields are marked **Yes**. Defaults in the table are schema defaults; additional',
    'workflow defaults are described in the guides. Expand **Full input schema** for nested',
    'objects, array items, enumerations, and all validation constraints. Open-ended `options`,',
    '`filter`, and `config` objects also undergo shared service validation; see the linked',
    'workflow examples for their accepted configuration.', '',
    'MCP annotations are discovery hints: `readOnlyHint` describes mutation behavior,',
    '`destructiveHint` flags potentially destructive changes, `idempotentHint` describes',
    'repeatability, and `openWorldHint` flags interaction beyond the local service. They do',
    'not grant permission. Required `confirm: true`, `confirmWriteback: true`, and `optIn: true`',
    'fields record explicit intent; underlying authorization and evidence gates still apply.', '',
    '## Tool index', '',
    '| Workflow | Tools |', '| --- | --- |',
    ...groups.map(([label, , names]) => `| ${label} | ${names.map(name => `[${inline(name)}](#${name})`).join(', ')} |`), '',
  ];
  for (const [label, anchor, names] of groups) {
    lines.push(`## ${label}`, '', `[Workflow guide and examples](mcp.md#${anchor}).`, '');
    for (const name of names) {
      const tool = byName.get(name);
      lines.push(`### ${inline(name)}`, '', tool.description, '',
        '**MCP annotations:** ' + Object.entries(tool.annotations || {}).map(([key, value]) => inline(`${key}=${value}`)).join(', ') + '.', '');
      const properties = Object.entries(tool.inputSchema.properties || {});
      if (properties.length) {
        lines.push('| Argument | Type | Required | Defaults and constraints |', '| --- | --- | --- | --- |');
        for (const [key, schema] of properties) lines.push(`| ${inline(key)} | ${type(schema)} | ${tool.inputSchema.required?.includes(key) ? '**Yes**' : 'No'} | ${constraints(schema)} |`);
      } else lines.push('No arguments. Send an empty `arguments` object (`{}`).');
      lines.push('', '<details>', '<summary>Full input schema</summary>', '', '```json', JSON.stringify(tool.inputSchema, null, 2), '```', '', '</details>', '');
    }
  }
  lines.push('## Keeping this reference current', '',
    'From a source checkout with the Workbench dependencies installed:', '',
    '```bash', 'npm --prefix web run docs:mcp', 'npm --prefix web run docs:mcp:check', '```', '',
    'The first command regenerates this page; the second fails when it differs from the',
    'registered tools. CI runs the check with the Workbench suite. Generation uses an',
    'in-memory protocol connection and inert services; it does not invoke tools, open a user',
    'profile, or contact providers. Update workflow guides alongside semantic changes.', '');
  return lines.join('\n');
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length && args[0] !== '--check')) throw new Error('Usage: node scripts/mcp-reference.cjs [--check]');
  const tools = await discover();
  const expected = render(tools);
  const filename = path.resolve(__dirname, '../../docs/mcp-tools.md');
  if (args[0] === '--check') {
    const actual = fs.existsSync(filename) ? fs.readFileSync(filename, 'utf8').replaceAll('\r\n', '\n') : '';
    if (actual !== expected) throw new Error('MCP reference is stale. Run npm --prefix web run docs:mcp and commit docs/mcp-tools.md.');
    console.log(`MCP reference matches all ${tools.length} registered tools.`);
  } else {
    fs.writeFileSync(filename, expected);
    console.log(`Generated docs/mcp-tools.md for ${tools.length} registered tools.`);
  }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
