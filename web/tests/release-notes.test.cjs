'use strict';
const { it } = require('node:test');
const assert = require('node:assert/strict');
const { releaseNotes } = require('../../.github/scripts/main-release-notes.cjs');
it('release notes include direct and merge commits in the exact push range without evaluating subjects', () => {
  const after = 'b'.repeat(40), before = 'a'.repeat(40);
  const notes = releaseNotes({ repository: 'example/threatlint', before, after, commits: [
    { sha: before, subject: 'Direct fix $(echo unsafe) `literal` <script> *text*' },
    { sha: after, subject: 'Merge pull request #12' },
  ] });
  assert.ok(notes.includes(`/compare/${before}...${after}`));
  assert.ok(notes.includes('Merge pull request #12'));
  assert.ok(notes.includes('$(echo unsafe)')); assert.ok(notes.includes('\\`literal\\`'));
  assert.equal(notes.includes('<script>'), false);
  assert.throws(() => releaseNotes({ repository: 'invalid/repo/path', after, commits: [] }));
});
