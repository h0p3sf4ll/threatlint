'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const { createRequire } = require('node:module');
const os = require('node:os');
const path = require('node:path');
const { describe, it, beforeEach, after } = require('node:test');
const { promisify } = require('node:util');
const vm = require('node:vm');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-snow-org-'));
const environmentKeys = ['THREATLINT_HOME', 'THREATLINT_AWS_REGION', 'THREATLINT_SNOW_INSTANCE',
  'THREATLINT_SNOW_CLIENT_ID_PARAMETER', 'THREATLINT_SNOW_CLIENT_SECRET_PARAMETER'];
const originalEnvironment = Object.fromEntries(environmentKeys.map(key => [key, process.env[key]]));
const saveOrg = values => fs.writeFileSync(path.join(home, 'org.json'), JSON.stringify(values));

// Load the real module with only its AWS subprocess transport replaced. No AWS executable is run.
const calls = [];
const execFile = () => assert.fail('Unexpected callback-based subprocess');
execFile[promisify.custom] = async (command, args, options) => {
  calls.push({ command, args: Array.from(args), options });
  const names = args.slice(args.indexOf('--names') + 1, args.indexOf('--with-decryption'));
  return { stdout: JSON.stringify({ Parameters: names.map(Name => ({ Name, Value: `value:${Name}` })) }) };
};
const filename = require.resolve('../lib/servicenow.cjs');
const localRequire = createRequire(filename);
const loaded = { exports: {} };
vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
  require: name => name === 'node:child_process' ? { execFile } : localRequire(name),
  module: loaded, process, URL, URLSearchParams, AbortSignal, Buffer,
}, { filename });
const { access, readParameters, readParameterStore, validateCredentials } = loaded.exports;

describe('ServiceNow organization defaults', () => {
  beforeEach(() => {
    calls.length = 0;
    for (const key of environmentKeys) delete process.env[key];
    process.env.THREATLINT_HOME = home;
    for (const file of ['org.json', 'servicenow.json']) fs.rmSync(path.join(home, file), { force: true });
  });
  after(() => {
    for (const [key, value] of Object.entries(originalEnvironment)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('preserves the default region in access help and AWS reads', async () => {
    assert.equal(access().region, 'us-west-2');
    assert.equal(access().parameterStoreUrl, 'https://us-west-2.console.aws.amazon.com/systems-manager/parameters/?region=us-west-2&tab=Table');
    await readParameters(['/security/token']);
    assert.equal(calls[0].args[calls[0].args.indexOf('--region') + 1], 'us-west-2');
  });

  it('uses the saved region and references for Parameter Store, with dynamic environment precedence', async () => {
    saveOrg({ awsRegion: 'eu-central-1', snowClientIdParameter: '/security/client-id', snowClientSecretParameter: '/security/client-secret' });
    assert.equal(access().region, 'eu-central-1');
    assert.equal(new URL(access().parameterStoreUrl).searchParams.get('region'), 'eu-central-1');
    const credentials = await readParameterStore({ profile: 'work-sso' });
    assert.equal(credentials.clientId, 'value:/security/client-id');
    assert.deepEqual(calls[0].args, ['ssm', 'get-parameters', '--names', '/security/client-id', '/security/client-secret',
      '--with-decryption', '--region', 'eu-central-1', '--output', 'json', '--profile', 'work-sso']);
    assert.equal(calls[0].command, 'aws');
    assert.equal(calls[0].options.windowsHide, true);

    process.env.THREATLINT_AWS_REGION = 'ap-southeast-2';
    assert.equal(access().region, 'ap-southeast-2');
    assert.equal(new URL(access().parameterStoreUrl).hostname, 'ap-southeast-2.console.aws.amazon.com');
    await readParameters(['/security/token']);
    assert.equal(calls[1].args[calls[1].args.indexOf('--region') + 1], 'ap-southeast-2');
  });

  it('accepts SSM parameter ARNs and rejects malformed inputs before invoking AWS', async () => {
    const arn = 'arn:aws-us-gov:ssm:us-gov-west-1:123456789012:parameter/security/token';
    await readParameters([arn]);
    assert.ok(calls[0].args.includes(arn));
    calls.length = 0;
    for (const names of [[], ['--endpoint-url'], ['name with spaces'], ['name\n'], [123], 'name']) {
      await assert.rejects(readParameters(names), /Invalid Parameter Store name/);
    }
    await assert.rejects(readParameters(['/token'], { profile: '--debug' }), /Invalid AWS profile/);
    process.env.THREATLINT_AWS_REGION = 'us-west-2 --endpoint-url=https://example.invalid';
    assert.throws(() => access(), /Invalid AWS region/);
    await assert.rejects(readParameters(['/token']), /Invalid AWS region/);
    assert.equal(calls.length, 0);
  });

  it('uses the organization instance only when request and saved instance are absent', () => {
    saveOrg({ snowInstance: 'https://org.service-now.com/' });
    const entered = { clientId: 'id', clientSecret: 'secret' };
    assert.equal(validateCredentials(entered).instance, 'https://org.service-now.com');
    fs.writeFileSync(path.join(home, 'servicenow.json'), JSON.stringify({ instance: 'https://saved.service-now.com' }));
    assert.equal(validateCredentials(entered).instance, 'https://saved.service-now.com');
    assert.equal(validateCredentials({ ...entered, instance: 'https://request.service-now.com' }).instance, 'https://request.service-now.com');
    fs.rmSync(path.join(home, 'servicenow.json'));
    process.env.THREATLINT_SNOW_INSTANCE = 'https://attacker.example';
    assert.throws(() => validateCredentials(entered), /not a ServiceNow host/);
  });
});
