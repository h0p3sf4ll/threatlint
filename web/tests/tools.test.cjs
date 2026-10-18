'use strict';
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isCommandSafe, safeResolvePath, executeTool } = require('../lib/tools.cjs');

let directory, outside;
before(() => {
  directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-tool-tests-'));
  outside = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-outside-'));
  fs.mkdirSync(path.join(directory, 'src'));
  fs.writeFileSync(path.join(directory, 'src/example.js'), 'const name = "visible";\nmodule.exports = name;\n');
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'outside-secret');
  fs.symlinkSync(outside, path.join(directory, 'escape'));
});
after(() => { fs.rmSync(directory, { recursive: true, force: true }); fs.rmSync(outside, { recursive: true, force: true }); });

describe('Actual read-only command parser', () => {
  for (const command of ['git log --oneline', 'git show HEAD', 'git diff HEAD~1', 'git status', 'git ls-files', 'find . -name "*.js"', 'grep -rn "name" src/', 'ls -la', 'cat src/example.js', 'sort -u src/example.js']) {
    it(`permits inspection: ${command}`, () => assert.equal(isCommandSafe(command), true));
  }
  for (const command of ['git log; touch owned', 'git status && node -e "1"', 'git remote add attacker https://example.com', 'git branch attacker', 'git tag attacker', 'git archive HEAD -o owned.zip', 'git show HEAD --output=owned', 'find . -delete', 'find . -exec touch owned \\;', 'cat file > owned', 'ls | cat', 'cat $(whoami)', 'python3 -c "print(1)"', 'node -e "console.log(1)"', 'env', 'printenv', 'awk "BEGIN{system(\"touch owned\")}"', 'sort -oowned src/example.js', 'uniq input output', 'curl https://example.com', 'git -c core.pager=evil log']) {
    it(`blocks mutation or escape: ${command}`, () => assert.equal(isCommandSafe(command), false));
  }
  it('never executes a shell operator hidden after a safe prefix', async () => {
    const result = await executeTool('Bash', { command: 'git status; touch owned' }, directory);
    assert.match(result, /not permitted/);
    assert.equal(fs.existsSync(path.join(directory, 'owned')), false);
  });
});

describe('Actual repository tool boundary', () => {
  it('reads numbered source lines', async () => {
    const result = await executeTool('Read', { file_path: 'src/example.js', offset: 1, limit: 1 }, directory);
    assert.match(result, /^2\tmodule.exports/);
    assert.doesNotMatch(result, /visible/);
  });
  it('denies sibling-prefix traversal, arbitrary tmp access, and symlink escapes', async () => {
    assert.equal(safeResolvePath(directory, `${directory}-other/file`), null);
    assert.equal(safeResolvePath(directory, path.join(outside, 'secret.txt')), null);
    assert.equal(safeResolvePath(directory, 'escape/secret.txt'), null);
    const result = await executeTool('Bash', { command: 'cat escape/secret.txt' }, directory);
    assert.match(result, /symlink|outside/);
    assert.doesNotMatch(result, /outside-secret/);
  });
  it('finds a root-level or nested file with a real glob implementation', async () => {
    assert.match(await executeTool('Glob', { pattern: '**/*.js' }, directory), /src\/example.js/);
    assert.doesNotMatch(await executeTool('Glob', { pattern: '**/*' }, directory), /escape/);
  });
  it('searches actual source with grep rather than executing interpolated commands', async () => {
    const result = await executeTool('Grep', { pattern: 'visible', path: 'src' }, directory);
    assert.match(result, /example.js:1:/);
    assert.match(result, /visible/);
  });
  it('does not read outside the selected repository when given a grep path', async () => {
    const result = await executeTool('Grep', { pattern: 'secret', path: outside }, directory);
    assert.match(result, /outside/);
    assert.doesNotMatch(result, /outside-secret/);
  });
});