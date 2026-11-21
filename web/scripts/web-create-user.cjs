'use strict';
const readline = require('node:readline');
const { Writable } = require('node:stream');
const { parseArgs } = require('node:util');
const { createAuth } = require('../lib/web-auth.cjs');
const { stateDirectory, acquireStateLock } = require('../lib/web-state.cjs');

async function password() {
  if (!process.stdin.isTTY) {
    // Automation may supply one password line on stdin, never a command-line argument.
    const input = readline.createInterface({ input: process.stdin });
    try { for await (const line of input) return line; }
    finally { input.close(); }
    throw new Error('A password is required on stdin');
  }
  const output = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  const input = readline.createInterface({ input: process.stdin, output, terminal: true });
  const ask = prompt => { process.stdout.write(prompt); return new Promise(resolve => input.question('', answer => { process.stdout.write('\n'); resolve(answer); })); };
  try {
    const first = await ask('Password (12–128 characters): ');
    if (first !== await ask('Confirm password: ')) throw new Error('Passwords did not match');
    return first;
  } finally { input.close(); }
}

async function main() {
  const { values } = parseArgs({ options: { email: { type: 'string' }, name: { type: 'string' } }, allowPositionals: false });
  if (!values.email) throw new Error('Usage: npm run web:create-user -- --email user@example.com --name "Name"');
  const directory = stateDirectory(), release = acquireStateLock(directory);
  try {
    const auth = createAuth({ directory });
    const result = await auth.register({ email: values.email, displayName: values.name, password: await password() });
    auth.logout({ headers: { cookie: `threatlint_session=${result.token}` } });
    console.log(`Account created: ${result.user.email}`);
  } finally { release(); }
}
main().catch(error => { console.error(error.message); process.exitCode = 1; });
