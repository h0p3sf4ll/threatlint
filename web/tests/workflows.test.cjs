'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const directory = path.join(__dirname, '../../.github/workflows');
const workflows = fs.readdirSync(directory).filter(name => /^appsec-.*\.yml$/.test(name))
  .map(name => ({ name, source: fs.readFileSync(path.join(directory, name), 'utf8') }))
  .filter(({ source }) => /^  push:/m.test(source));

describe('Push-triggered Claude workflows', () => {
  it('uses the standalone action rather than the PR/issue event wrapper', () => {
    assert.equal(workflows.length, 3);
    for (const { name, source } of workflows) {
      assert.match(source, /uses: anthropics\/claude-code-action\/base-action@[a-f0-9]{40}\b/, name);
      assert.doesNotMatch(source, /uses: anthropics\/claude-code-action@/, name);
    }
  });

  it('checks Claude credentials before starting a model action', () => {
    for (const { name, source } of workflows) {
      const preflight = source.indexOf('- name: Validate Claude credentials');
      const action = source.indexOf('uses: anthropics/claude-code-action');
      assert.ok(preflight >= 0 && preflight < action, name);
      const block = source.slice(preflight, action);
      assert.match(block, /if: env\.PROVIDER == 'claude'/, name);
      assert.match(block, /ANTHROPIC_API_KEY: \$\{\{ secrets\.ANTHROPIC_API_KEY \}\}/, name);
      assert.match(block, /::error::Configure ANTHROPIC_API_KEY/, name);
      assert.match(block, /exit 1/, name);
    }
  });
});
