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

  it('preserves Windows PATH separators, drive letters, and environment key casing without probing a shell', () => {
    for (const key of ['PATH', 'Path', 'path']) {
      const value = 'C:\\Users\\me\\bin;C:\\Windows\\System32;D:\\Tools';
      const env = { [key]: value, TEMP: 'C:\\Temp' };
      const options = { env, platform: 'win32', spawnSyncImpl: () => assert.fail('Windows must not launch a POSIX login shell') };
      assert.equal(userPath(options), value);
      assert.equal(adoptUserPath(options), value);
      assert.deepEqual(env, { [key]: value, TEMP: 'C:\\Temp' });
    }
  });

  it('uses POSIX syntax for Linux as well as macOS regardless of the test host', () => {
    assert.equal(userPath({ env: { PATH: '/usr/bin:/bin' }, platform: 'linux', spawnSyncImpl: shellSays('__PATH__/home/me/.local/bin:/usr/bin__END__') }),
      '/home/me/.local/bin:/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin');
  });
});
