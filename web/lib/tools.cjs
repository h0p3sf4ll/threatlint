'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { parse } = require('shell-quote');
const { minimatch } = require('minimatch');
const execFileAsync = promisify(execFile);

const GIT_COMMANDS = new Set(['log', 'show', 'ls-files', 'status', 'diff', 'blame', 'rev-parse', 'ls-tree', 'describe', 'shortlog', 'grep', 'rev-list', 'check-ignore']);
const READ_COMMANDS = new Set(['find', 'grep', 'rg', 'cat', 'head', 'tail', 'wc', 'ls', 'file', 'stat', 'basename', 'dirname', 'sort', 'uniq', 'cut']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', '__pycache__', 'release']);

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function safeResolvePath(repoPath, filePath) {
  if (typeof filePath !== 'string' || !filePath || filePath.includes('\0')) return null;
  try {
    const root = fs.realpathSync(repoPath);
    const resolved = fs.realpathSync(path.resolve(root, filePath));
    return inside(root, resolved) ? resolved : null;
  } catch { return null; }
}

const OUTPUT_OR_HOOK_FLAG = /^(-{1,2}(?:output|exec|ext-diff|textconv|config|files-from|pre|include|file-list|out)(?:=|$)|--(?:open|sort-files)|-[of]$)/;
const GIT_UNSAFE_FLAG = /^(?:--(?:git-dir|work-tree|upload-pack|receive-pack|exec-path|output|no-index|ext-diff|textconv)|-[cC]$)/;

// Per-program argument checks; each returns true when an argument set must be rejected.
const PROGRAM_DENY = {
  git: rest => !GIT_COMMANDS.has(rest[0]) || rest.some(arg => GIT_UNSAFE_FLAG.test(arg)),
  find: rest => rest.some(arg => /^-(?:exec|execdir|ok|okdir|delete|fprint|fprintf|fls)/.test(arg)),
  sort: rest => rest.some(arg => /^-[oT]/.test(arg) || arg.startsWith('--compress-program') || arg.startsWith('--temporary-directory')),
  uniq: rest => rest.filter(arg => !arg.startsWith('-')).length > 1,
  rg: rest => rest.some(arg => /^(?:--(?:pre|hostname-bin)|--no-ignore|--follow|-L$)/.test(arg)),
  grep: rest => rest.some(arg => /^-[^-]*R/.test(arg) || arg === '--dereference-recursive'),
};

function tokenize(command) {
  if (typeof command !== 'string' || command.length > 8000 || /[\r\n\0]/.test(command)) return null;
  try {
    const args = parse(command, () => { throw new Error('Variable expansion is not allowed'); });
    return args.length && args.every(token => typeof token === 'string') ? args : null;
  } catch { return null; }
}

function parseReadCommand(command) {
  const args = tokenize(command);
  if (!args) return null;
  const [program, ...rest] = args;
  // No shell, interpreters, repository scripts, env inspection, output flags, or command hooks.
  if (rest.some(arg => OUTPUT_OR_HOOK_FLAG.test(arg))) return null;
  if (program !== 'git' && !READ_COMMANDS.has(program)) return null;
  if (PROGRAM_DENY[program]?.(rest)) return null;
  return { program, args: rest };
}

function isCommandSafe(command) { return !!parseReadCommand(command); }

function looksLikePath(repoPath, arg) {
  if (/^(?:\/|\.\.?$|\.\.?[\\/]|~[\\/])/.test(arg)) return true;
  if (fs.existsSync(path.resolve(repoPath, arg))) return true;
  return arg.includes('/') && !arg.includes('://') && !arg.includes('[');
}

function verifyCommandPaths(repoPath, program, args) {
  // Check explicit path-shaped arguments, including non-existent destinations, against symlinks.
  const candidates = args.filter(arg => arg && !arg.startsWith('-') && !arg.includes('*') && looksLikePath(repoPath, arg));
  for (const arg of candidates) {
    const resolved = path.resolve(repoPath, arg);
    if (!inside(repoPath, resolved)) throw new Error('Command path is outside the repository');
    if (fs.existsSync(resolved) && !safeResolvePath(repoPath, arg)) throw new Error('Command path escapes through a symlink');
  }
  if (program === 'find' && args.includes('-L')) throw new Error('Following symlinks is not allowed');
}

function readDirectory(directory) {
  try { return fs.readdirSync(directory, { withFileTypes: true }); } catch { return []; }
}

function walkFiles(root, limit = 20_000) {
  const files = [];
  const stack = [''];
  while (stack.length && files.length < limit) {
    const relative = stack.pop();
    for (const entry of readDirectory(path.join(root, relative))) {
      if (files.length >= limit) break;
      if (entry.isSymbolicLink()) continue;
      const candidate = path.join(relative, entry.name);
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) stack.push(candidate);
      else if (entry.isFile()) files.push(candidate.split(path.sep).join('/'));
    }
  }
  return files.sort((a, b) => (a < b ? -1 : Number(a > b)));
}

const READ_MAX_BYTES = 2 * 1024 * 1024;
const GREP_FILE_MAX_BYTES = 1024 * 1024;
const GREP_MAX_FILES = 3000;
const GREP_BATCH = 100;
const OUTPUT_LIMIT = 50_000;
const integerOr = (value, fallback) => (Number.isInteger(value) ? value : fallback);

function readTool(root, input) {
  const resolved = safeResolvePath(root, input.file_path || input.path || input.filePath);
  if (!resolved) return 'Error: file not found or access outside the repository denied';
  const stats = fs.statSync(resolved);
  if (!stats.isFile()) return 'Error: path is not a file';
  if (stats.size > READ_MAX_BYTES) return 'Error: file exceeds the 2 MB inspection limit';
  const start = Math.max(0, integerOr(input.offset, 0));
  const count = Math.min(2000, Math.max(1, integerOr(input.limit, 500)));
  return fs.readFileSync(resolved, 'utf8').split('\n').slice(start, start + count).map((line, i) => `${start + i + 1}\t${line}`).join('\n');
}

function globTool(root, input) {
  if (typeof input.pattern !== 'string' || input.pattern.length > 500) return 'Error: a bounded glob pattern is required';
  const matches = walkFiles(root).filter(file => minimatch(file, input.pattern, { dot: true }));
  return matches.slice(0, 1000).join('\n') || '(no matches within the 20,000-file inventory limit)';
}

// Runs grep over fixed-size batches one after another so output stays bounded and ordered.
async function grepBatches(root, flags, pattern, files, index = 0, result = '') {
  if (index >= files.length || result.length >= OUTPUT_LIMIT) return result;
  let stdout = '';
  try {
    ({ stdout } = await execFileAsync('grep', [flags, '-e', pattern, '--', ...files.slice(index, index + GREP_BATCH)], { cwd: root, timeout: 10_000, maxBuffer: 1024 * 1024 }));
  } catch (error) {
    if (error.code !== 1) throw new Error(error.message.slice(0, 300));
  }
  return grepBatches(root, flags, pattern, files, index + GREP_BATCH, result + stdout);
}

async function grepTool(root, input) {
  if (typeof input.pattern !== 'string' || input.pattern.length > 1000) return 'Error: a bounded pattern is required';
  const target = safeResolvePath(root, input.path || '.');
  if (!target) return 'Error: search path is outside the repository';
  const files = fs.statSync(target).isFile() ? [target] : walkFiles(target).map(file => path.join(target, file));
  // Use grep's regex engine rather than an unbounded model-controlled JavaScript regex.
  const selected = files.filter(file => fs.statSync(file).size <= GREP_FILE_MAX_BYTES).slice(0, GREP_MAX_FILES);
  const flags = String(input.flags || '').includes('i') ? '-nHiE' : '-nHE';
  try {
    const result = await grepBatches(root, flags, input.pattern, selected);
    return result.slice(0, OUTPUT_LIMIT) || '(no matches within inspection limits)';
  } catch (error) { return `Error: ${error.message}`; }
}

function gitArguments(args) {
  const [subcommand, ...rest] = args;
  const noExternalDiff = ['log', 'show', 'diff'].includes(subcommand) ? ['--no-ext-diff', '--no-textconv'] : [];
  return ['--no-pager', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.pager=cat', subcommand, ...noExternalDiff, ...rest];
}

async function bashTool(root, input) {
  const parsed = parseReadCommand(input.command || input.cmd);
  if (!parsed) return 'Error: command not permitted; use one read-only command without shell operators';
  verifyCommandPaths(root, parsed.program, parsed.args);
  const args = parsed.program === 'git' ? gitArguments(parsed.args) : parsed.args;
  const env = { PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'en_US.UTF-8', GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: osNull(), RG_CONFIG_PATH: '' };
  const { stdout, stderr } = await execFileAsync(parsed.program, args, { cwd: root, env, timeout: 30_000, maxBuffer: 2 * 1024 * 1024, windowsHide: true });
  return (stdout + stderr).slice(0, OUTPUT_LIMIT);
}

const TOOLS = { Read: readTool, Glob: globTool, Grep: grepTool, Bash: bashTool };

async function executeTool(name, input, repoPath) {
  try {
    const tool = Object.hasOwn(TOOLS, name) ? TOOLS[name] : null;
    if (!tool) return `Error: unknown tool ${name}`;
    return await tool(fs.realpathSync(repoPath), input || {});
  } catch (error) { return `Tool error: ${String(error.message).slice(0, 500)}`; }
}

function osNull() { return process.platform === 'win32' ? 'NUL' : '/dev/null'; }

module.exports = { executeTool, isCommandSafe, parseReadCommand, safeResolvePath, walkFiles, inside };
