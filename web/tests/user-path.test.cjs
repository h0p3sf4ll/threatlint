'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { userPath, adoptUserPath, loginShellPath } = require('../desktop/user-path.cjs');

const shellSays = stdout => () => ({ stdout });

describe('desktop user PATH', () => {
  it('puts the login shell PATH first, keeps the inherited one, and drops duplicates', () => {
    const merged = userPath({ env: { PATH: '/usr/bin:/bin' }, platform: 'darwin', spawnSyncImpl: shellSays('motd noise\n__PATH__/Users/me/.local/bin:/opt/homebrew/bin:/usr/bin__END__') });
    assert.equal(merged, '/Users/me/.local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/local/bin');
  });

  it('still adds common install dirs when the shell cannot be read', () => {
    assert.equal(loginShellPath({ spawnSyncImpl: () => ({ stdout: null }) }), '');
    assert.equal(userPath({ env: { PATH: '/usr/bin' }, platform: 'darwin', spawnSyncImpl: () => ({}) }), '/usr/bin:/opt/homebrew/bin:/usr/local/bin');
  });

  it('leaves Windows alone and updates the given environment', () => {
    assert.equal(userPath({ env: { PATH: 'C:\\Windows' }, platform: 'win32' }), 'C:\\Windows');
    const env = { PATH: '/usr/bin' };
    adoptUserPath({ env, platform: 'darwin', spawnSyncImpl: shellSays('__PATH__/opt/tools__END__') });
    assert.equal(env.PATH, '/opt/tools:/usr/bin:/opt/homebrew/bin:/usr/local/bin');
  });
});
