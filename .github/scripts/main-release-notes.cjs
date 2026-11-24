'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

function releaseNotes({ repository, before, after, commits }) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository) || !/^[a-f0-9]{40}$/.test(after)) throw new Error('Invalid release repository or commit');
  const escape = value => value.replace(/[\\`*_\[\]<>]/g, '\\$&').replace(/[\r\n]+/g, ' ');
  const base = `https://github.com/${repository}`;
  const changes = commits.slice(0, 100).map(({ sha, subject }) => {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error('Invalid commit');
    return `- [${sha.slice(0, 12)}](${base}/commit/${sha}) ${escape(subject.slice(0, 300))}`;
  });
  if (commits.length > 100) changes.push(`- ${commits.length - 100} additional commits are included in the comparison below.`);
  return `# Main build ${after.slice(0, 12)}\n\nChanges published to main in this push.\n\n${changes.join('\n') || 'No additional commits.'}\n\n${/^[a-f0-9]{40}$/.test(before || '') && !/^0+$/.test(before) ? `[Compare this push](${base}/compare/${before}...${after})` : `[View commit](${base}/commit/${after})`}\n\nThese notes describe source changes. Build and deployment workflows report their own status.\n`;
}

function main() {
  if (process.env.GITHUB_REF !== 'refs/heads/main') throw new Error('Release notes are published only from main');
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const repository = process.env.GITHUB_REPOSITORY, after = process.env.GITHUB_SHA;
  const before = event.before && !/^0+$/.test(event.before) ? event.before : '';
  if (!/^[a-f0-9]{40}$/.test(after || '') || (before && !/^[a-f0-9]{40}$/.test(before))) throw new Error('Invalid release range');
  const run = (command, args) => execFileSync(command, args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  // Subjects are data passed to a file; they never become shell arguments or workflow expressions.
  const range = before ? `${before}..${after}` : after;
  const raw = run('git', ['log', '--reverse', '--format=%H%x00%s', ...(before ? [] : ['-1']), range]);
  const commits = raw.trim().split('\n').filter(Boolean).map(line => { const [sha, subject] = line.split('\0'); return { sha, subject }; });
  const notes = releaseNotes({ repository, before, after, commits });
  const tag = `main-${after.slice(0, 12)}`;
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-release-'));
  const file = path.join(directory, 'notes.md');
  try {
    fs.writeFileSync(file, notes);
    let exists = false;
    try { run('gh', ['release', 'view', tag, '--repo', repository, '--json', 'tagName']); exists = true; }
    catch (error) { if (error.status !== 1) throw error; }
    run('gh', exists ? ['release', 'edit', tag, '--repo', repository, '--notes-file', file]
      : ['release', 'create', tag, '--repo', repository, '--target', after, '--title', `Main build ${after.slice(0, 12)}`, '--notes-file', file, '--prerelease']);
    console.log(`Release notes published: ${tag}`);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}
if (require.main === module) main();
module.exports = { releaseNotes };
