'use strict';

// From the checkout: node web/examples/mcp-client.cjs ABSOLUTE_REPO_PATH ABSOLUTE_STATE_DIR
// Runs the model-free baseline scanner. State must be outside the scanned repository.
const fs = require('node:fs');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

async function main() {
  const [repoArgument, stateArgument] = process.argv.slice(2);
  if (!path.isAbsolute(repoArgument || '') || !path.isAbsolute(stateArgument || '')) {
    throw new Error('Usage: node web/examples/mcp-client.cjs ABSOLUTE_REPO_PATH ABSOLUTE_STATE_DIR');
  }
  const repoPath = fs.realpathSync(repoArgument), statePath = path.resolve(stateArgument);
  if (!fs.statSync(repoPath).isDirectory()) throw new Error('Repository path must be a directory');
  let existingParent = statePath;
  while (!fs.existsSync(existingParent)) existingParent = path.dirname(existingParent);
  const realState = path.resolve(fs.realpathSync(existingParent), path.relative(existingParent, statePath));
  const relative = path.relative(repoPath, realState);
  if (relative === '' || relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)) {
    throw new Error('Use a state directory outside the scanned repository so profile files do not affect the scan');
  }
  const transport = new StdioClientTransport({ command: process.execPath,
    args: [path.resolve(__dirname, '../scripts/mcp.cjs')], stderr: 'inherit',
    env: { ...Object.fromEntries(Object.entries(process.env).filter(([, value]) => typeof value === 'string')), THREATLINT_STATE_DIR: realState } });
  const client = new Client({ name: 'threatlint-headless-example', version: '1.0.0' });
  async function call(name, input = {}) {
    const response = await client.callTool({ name, arguments: input });
    if (response.isError) throw new Error(response.content.filter(item => item.type === 'text').map(item => item.text).join('\n'));
    return response.structuredContent?.result ?? JSON.parse(response.content.find(item => item.type === 'text').text);
  }
  try {
    await client.connect(transport);
    const agents = await call('list_agents');
    const workspace = await call('open_workspace', { repoPath, confirm: true });
    console.log(JSON.stringify({ specialists: agents.length, workspace }, null, 2));
    const { id: scanId } = await call('start_scan', { sessionId: workspace.sessionId, engines: [], confirm: true });
    const deadline = Date.now() + 10 * 60_000;
    for (;;) {
      const scan = await call('get_scan', { sessionId: workspace.sessionId, scanId });
      if (scan.status !== 'running') {
        console.log(JSON.stringify(scan, null, 2));
        if (scan.status === 'failed' || scan.status === 'cancelled') process.exitCode = 1;
        break;
      }
      if (Date.now() > deadline) {
        await call('cancel_scan', { sessionId: workspace.sessionId, scanId, confirm: true });
        throw new Error('Scan timed out; cancellation requested');
      }
      await delay(500);
    }
  } finally {
    await client.close();
    await transport.close();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
