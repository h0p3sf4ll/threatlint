'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const { userPath, adoptUserPath, loginShellPath, windowsRegistryPath } = require('../desktop/user-path.cjs');

const shellSays = stdout => () => ({ stdout });
const registrySays = stdout => () => ({ status: 0, stdout });

describe('desktop user PATH', () => {
  it('puts the login shell PATH first, keeps the inherited one, and drops duplicates', () => {
    const merged = userPath({ env: { PATH: '/usr/bin:/bin' }, platform: 'darwin', spawnSyncImpl: shellSays('motd noise\n__PATH__/Users/me/.local/bin:/opt/homebrew/bin:/usr/bin__END__') });
    assert.equal(merged, '/Users/me/.local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/local/bin');
  });

  it('still adds common install dirs when the shell cannot be read', () => {
    assert.equal(loginShellPath({ spawnSyncImpl: () => ({ stdout: null }) }), '');
    assert.equal(userPath({ env: { PATH: '/usr/bin' }, platform: 'darwin', spawnSyncImpl: () => ({}) }), '/usr/bin:/opt/homebrew/bin:/usr/local/bin');
  });

  it('preserves Windows drive letters and semicolon entries when User PATH is empty', () => {
    const env = { PATH: 'C:\\Windows;C:\\Program Files\\Git\\cmd;D:\\tools' };
    const result = userPath({ env, platform: 'win32', spawnSyncImpl: registrySays('') });
    assert.equal(result, env.PATH);
  });
  it('keeps Windows inherited PATH on registry failure and updates the given environment', () => {
    assert.equal(userPath({ env: { PATH: 'C:\\Windows' }, platform: 'win32', spawnSyncImpl: () => ({ status: 1 }) }), 'C:\\Windows');
    const env = { PATH: '/usr/bin' };
    adoptUserPath({ env, platform: 'darwin', spawnSyncImpl: shellSays('__PATH__/opt/tools__END__') });
    assert.equal(env.PATH, '/opt/tools:/usr/bin:/opt/homebrew/bin:/usr/local/bin');
  });

  it('preserves Windows PATH separators, drive letters, and environment key casing', () => {
    for (const key of ['PATH', 'Path', 'path']) {
      const value = 'C:\\Users\\me\\bin;C:\\Windows\\System32;D:\\Tools';
      const env = { [key]: value, TEMP: 'C:\\Temp' };
      const options = { env, platform: 'win32', spawnSyncImpl: registrySays('') };
      assert.equal(userPath(options), value);
      assert.equal(adoptUserPath(options), value);
      assert.deepEqual(env, { [key]: value, TEMP: 'C:\\Temp' });
    }
  });

  it('uses POSIX syntax for Linux as well as macOS regardless of the test host', () => {
    assert.equal(userPath({ env: { PATH: '/usr/bin:/bin' }, platform: 'linux', spawnSyncImpl: shellSays('__PATH__/home/me/.local/bin:/usr/bin__END__') }),
      '/home/me/.local/bin:/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin');
  });

  it('appends a newly installed user tool while retaining inherited command precedence', () => {
    const env = { Path: 'C:\\Windows\\System32;C:\\TrustedTools', SystemRoot: 'C:\\Windows' };
    const fresh = 'D:\\UserTools\\Semgrep\\Scripts;C:\\TrustedTools';
    assert.equal(adoptUserPath({ env, platform: 'win32', spawnSyncImpl: registrySays(fresh) }),
      'C:\\Windows\\System32;C:\\TrustedTools;D:\\UserTools\\Semgrep\\Scripts');
    assert.equal(Object.hasOwn(env, 'PATH'), false);
  });

  it('expands user variables case-insensitively and deduplicates Windows spelling variants', () => {
    const env = { PATH: 'C:\\Windows\\System32;C:\\Users\\Me\\Tools', USERPROFILE: 'C:\\Users\\Me',
      LocalAppData: 'C:\\Users\\Me\\AppData\\Local', TOOL_ROOT: '%localappdata%\\ThreatlintTools' };
    assert.equal(userPath({ env, platform: 'win32', spawnSyncImpl: registrySays(
      '%userprofile%\\tools\\;c:/WINDOWS/System32;%tool_root%\\Scripts;C:\\Users\\Me\\工具') }),
    'C:\\Windows\\System32;C:\\Users\\Me\\Tools;C:\\Users\\Me\\AppData\\Local\\ThreatlintTools\\Scripts;C:\\Users\\Me\\工具');
  });

  it('reads exactly User Path with a fully qualified, fixed, bounded hidden PowerShell command', () => {
    let invocation;
    const env = { Path: 'C:\\Windows', systemroot: 'D:\\Windows', USERPROFILE: 'C:\\Users\\name;not-code' };
    assert.equal(windowsRegistryPath({ env, spawnSyncImpl: (...args) => {
      invocation = args; return { status: 0, stdout: 'D:\\工具\\Scripts' };
    } }), 'D:\\工具\\Scripts');
    const [file, args, options] = invocation;
    assert.equal(file, 'D:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    assert.deepEqual(args.slice(0, 4), ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command']);
    assert.equal(args[4], "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false); $value = [Environment]::GetEnvironmentVariable('Path', 'User'); if ($null -ne $value) { [Console]::Out.Write($value) }");
    assert.equal(args[4].includes(env.USERPROFILE), false);
    assert.equal(options.shell, false); assert.equal(options.windowsHide, true);
    assert.equal(options.timeout, 8000); assert.equal(options.maxBuffer, 65536); assert.equal(options.encoding, 'utf8');
    assert.equal(options.env, env);
  });

  it('keeps drive roots distinct from drive-relative paths and deduplicates quoted Unicode entries', () => {
    const env = { Path: 'C:\\;C:; "D:\\工具 目录" ' };
    assert.equal(userPath({ env, platform: 'win32', spawnSyncImpl: registrySays(
      'c:\\;c:;d:/工具 目录/;E:\\Tools\\;e:\\tools') }), 'C:\\;C:;"D:\\工具 目录";E:\\Tools\\');
  });

  it('falls back unchanged for empty, missing, timed-out, failed, or malformed registry reads', () => {
    const inherited = 'C:\\Windows;D:\\Existing';
    const responses = [{ status: 0, stdout: '' }, { status: 0, stdout: '   ' }, { status: 1, stdout: 'bad' },
      { error: new Error('timeout'), status: null, stdout: 'partial' }, { status: 0, stdout: null },
      { status: 0, stdout: 'D:\\Tools\nnoise' }, { status: 0, stdout: 'D:\\Tools\0' },
      { status: 0, stdout: 'x'.repeat(65537) }];
    for (const result of responses) assert.equal(userPath({ env: { PATH: inherited }, platform: 'win32', spawnSyncImpl: () => result }), inherited);
    assert.equal(userPath({ env: { PATH: inherited }, platform: 'win32', spawnSyncImpl: () => { throw new Error('unavailable'); } }), inherited);
  });
});
