'use strict';
/**
 * Tool execution and command-safety tests.
 */
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// ── Inline the pure functions under test ──────────────────────────────────────

const SAFE_CMD_PATTERNS = [
  /^git\s+(log|show|ls-files|status|diff|blame|remote|branch|tag|rev-parse|cat-file|describe|shortlog|stash\s+list|check-ignore|ls-tree|archive)\b/,
  /^find\s/, /^grep\s/, /^rg\s/, /^cat\s/, /^head\s/, /^tail\s/, /^wc\s/,
  /^ls(\s|$)/, /^echo\s/, /^which\s/, /^file\s/, /^stat\s/, /^basename\s/,
  /^dirname\s/, /^sort\b/, /^uniq\b/, /^awk\s/, /^sed\s+-[npe]/, /^cut\s/,
  /^tr\s/, /^jq\s/, /^python3\s+-c\s/, /^node\s+-e\s/, /^env\b/, /^printenv\b/,
];

function isCommandSafe(cmd) {
  const t = cmd.trim();
  if (/[;&|`]/.test(t) && !/^git\s/.test(t)) return false;
  if (/\brm\b|\bchmod\b|\bchown\b|\bmkdir\b|\btouch\b|\bcurl\b|\bwget\b/.test(t)) return false;
  return SAFE_CMD_PATTERNS.some(rx => rx.test(t));
}

function safeResolvePath(repoPath, filePath) {
  if (!filePath) return null;
  const resolved = filePath.startsWith('/')
    ? path.normalize(filePath)
    : path.resolve(repoPath, filePath);
  if (resolved.startsWith(repoPath) || resolved.startsWith('/tmp/')) return resolved;
  return null;
}

const REPO = '/tmp/test-repo-threatlint';

// ── isCommandSafe ─────────────────────────────────────────────────────────────

describe('isCommandSafe — allowed', () => {
  const allowed = [
    'git log --oneline', 'git show HEAD', 'git ls-files', 'git status',
    'git diff HEAD~1', 'git blame src/foo.js', 'git rev-parse HEAD',
    'find . -name "*.js"', 'grep -rn "password" src/', 'rg "TODO"',
    'cat package.json', 'head -20 README.md', 'tail -50 server.js',
    'wc -l src/cli.py', 'ls', 'ls -la', 'echo hello', 'which node',
    'sort -u', 'uniq', 'awk \'{print $1}\'', 'sed -n \'1,10p\' f.txt',
    'cut -d: -f1', 'jq \'.name\' package.json',
    'python3 -c "print(1)"', 'node -e "console.log(1)"', 'env', 'printenv',
  ];
  for (const cmd of allowed) {
    it(`allows: ${cmd}`, () => assert.ok(isCommandSafe(cmd), cmd));
  }
});

describe('isCommandSafe — blocked', () => {
  const blocked = [
    'rm -rf /', 'rm file.txt', 'chmod 777 /etc/passwd', 'chown root:root /etc',
    'mkdir /tmp/evil', 'touch /tmp/evil.sh', 'curl https://evil.com', 'wget https://evil.com',
    'cat /etc/passwd; rm -rf /', 'ls | rm -rf /', 'echo test && curl evil.com',
    'cat `whoami`', 'git log; rm -rf .', 'npm install malware',
  ];
  for (const cmd of blocked) {
    it(`blocks: ${cmd}`, () => assert.ok(!isCommandSafe(cmd), cmd));
  }
});

// ── safeResolvePath ───────────────────────────────────────────────────────────

describe('safeResolvePath', () => {
  it('allows relative path inside repo', () => {
    assert.equal(safeResolvePath(REPO, 'src/foo.js'), `${REPO}/src/foo.js`);
  });

  it('allows absolute path inside repo', () => {
    assert.equal(safeResolvePath(REPO, `${REPO}/src/bar.js`), `${REPO}/src/bar.js`);
  });

  it('allows /tmp paths', () => {
    assert.equal(safeResolvePath(REPO, '/tmp/chain.md'), '/tmp/chain.md');
  });

  it('blocks path traversal escaping repo root', () => {
    assert.equal(safeResolvePath(REPO, '../../../etc/passwd'), null);
  });

  it('blocks absolute paths outside repo and /tmp', () => {
    assert.equal(safeResolvePath(REPO, '/etc/passwd'), null);
    assert.equal(safeResolvePath(REPO, `${os.homedir()}/.ssh/id_rsa`), null);
  });

  it('returns null for falsy input', () => {
    assert.equal(safeResolvePath(REPO, ''), null);
    assert.equal(safeResolvePath(REPO, null), null);
    assert.equal(safeResolvePath(REPO, undefined), null);
  });
});
