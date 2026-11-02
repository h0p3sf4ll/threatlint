'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { parseArgs, exportPacket, loadRecordings, probeAudio } = require('../scripts/video-narration.cjs');
const { recordingPlan } = require('../scripts/build-videos.cjs');
const { VIDEOS } = require('../lib/help.cjs');

function packet(t, ids = ['overview']) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-narration-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const videos = recordingPlan(ids);
  const manifest = exportPacket(directory, videos);
  return { directory, videos, manifest };
}

function recordings(directory, manifest) {
  for (const video of manifest.videos) for (const scene of video.scenes) {
    fs.writeFileSync(path.join(directory, scene.file), 'synthetic audio fixture, not narration');
  }
}

describe('Human narration workflow', () => {
  it('exports every library video with matching scene text and stable take names', t => {
    const { directory, videos, manifest } = packet(t, []);
    assert.deepEqual(videos.map(video => video.id), VIDEOS.map(video => video.id));
    for (const video of manifest.videos) {
      const script = fs.readFileSync(path.join(directory, 'scripts', `${video.id}.md`), 'utf8');
      assert.equal(video.scenes.length, videos.find(item => item.id === video.id).scenes.length);
      for (const scene of video.scenes) assert.ok(script.includes(scene.text) && script.includes(scene.file));
      assert.match(video.scenes[0].file, /\/01\.wav$/);
    }
    assert.match(fs.readFileSync(path.join(directory, 'README.md'), 'utf8'), /human female narrator/i);
  });

  it('does not overwrite a recording packet or existing takes', t => {
    const { directory, videos, manifest } = packet(t);
    recordings(directory, manifest);
    assert.throws(() => exportPacket(directory, videos), /not empty/);
    assert.match(fs.readFileSync(path.join(directory, manifest.videos[0].scenes[0].file), 'utf8'), /fixture/);
  });

  it('requires recorded audio and never substitutes TTS', t => {
    const { directory, videos, manifest } = packet(t);
    assert.throws(() => loadRecordings(directory, videos), /Missing or empty human recording/);
    recordings(directory, manifest);
    fs.writeFileSync(path.join(directory, manifest.videos[0].scenes[0].file), '');
    assert.throws(() => loadRecordings(directory, videos), /Missing or empty human recording/);
    assert.throws(() => parseArgs([]), /Synthetic speech is not a fallback/);
  });

  it('imports recordings in scene order with their actual durations', t => {
    const { directory, videos, manifest } = packet(t);
    recordings(directory, manifest);
    let count = 0;
    const imported = loadRecordings(directory, videos, { probe: () => ++count * 1.25 });
    assert.deepEqual(imported.get('overview').map(clip => clip.seconds), videos[0].scenes.map((_scene, index) => (index + 1) * 1.25));
    assert.equal(imported.get('overview')[0].file, path.join(directory, 'audio/overview/01.wav'));
  });

  it('rejects stale wording before using an old recording', t => {
    const { directory, videos, manifest } = packet(t);
    recordings(directory, manifest);
    videos[0].scenes[0] = { ...videos[0].scenes[0], say: 'A new script revision.' };
    assert.throws(() => loadRecordings(directory, videos, { probe: () => 1 }), /script changed/);
  });

  it('rejects unexpected take paths, duplicate videos, and invalid manifests', t => {
    const { directory, videos, manifest } = packet(t);
    manifest.videos[0].scenes[0].file = '../outside.wav';
    const file = path.join(directory, 'manifest.json');
    fs.writeFileSync(file, JSON.stringify(manifest));
    assert.throws(() => loadRecordings(directory, videos), /script changed/);
    manifest.videos.push(manifest.videos[0]);
    fs.writeFileSync(file, JSON.stringify(manifest));
    assert.throws(() => loadRecordings(directory, videos), /scenes do not match/);
    fs.writeFileSync(file, '{"version":99,"videos":[]}');
    assert.throws(() => loadRecordings(directory, videos), /Unsupported narration manifest/);
  });

  it('rejects invalid durations rather than producing a misleading clip', t => {
    const { directory, videos, manifest } = packet(t);
    recordings(directory, manifest);
    for (const seconds of [0, -1, NaN, Infinity]) {
      assert.throws(() => loadRecordings(directory, videos, { probe: () => seconds }), /Invalid recording duration/);
    }
  });

  it('probes real audio metadata without needing ffprobe in the unit suite', () => {
    const metadata = { format: { format_name: 'wav', duration: '3.25' }, streams: [{ codec_type: 'audio', channels: 1, sample_rate: '48000' }] };
    const run = (command, args) => {
      assert.equal(command, 'ffprobe');
      assert.equal(args.at(-1), 'take.wav');
      return JSON.stringify(metadata);
    };
    assert.equal(probeAudio('take.wav', { run }), 3.25);
    metadata.streams[0].channels = 2;
    assert.equal(probeAudio('take.wav', { run }), 3.25);
    for (const invalid of [
      { ...metadata, streams: [] },
      { ...metadata, streams: [{ codec_type: 'video' }] },
      { ...metadata, streams: [{ codec_type: 'audio', channels: 6, sample_rate: '48000' }] },
      { ...metadata, format: { format_name: 'mp3', duration: '3.25' } },
      { ...metadata, format: { format_name: 'wav', duration: 'NaN' } },
    ]) {
      assert.throws(() => probeAudio('take.wav', { run: () => JSON.stringify(invalid) }), /non-empty mono or stereo WAV/);
    }
    assert.throws(() => probeAudio('take.wav', { run: () => { throw Object.assign(new Error('missing'), { code: 'ENOENT' }); } }), /ffprobe is required/);
    assert.throws(() => probeAudio('take.wav', { run: () => { throw new Error('invalid data'); } }), /Cannot read WAV recording/);
  });

  it('rejects scene count changes and malformed manifest entries', t => {
    const { directory, videos, manifest } = packet(t);
    const file = path.join(directory, 'manifest.json');
    manifest.videos[0].scenes.pop();
    fs.writeFileSync(file, JSON.stringify(manifest));
    assert.throws(() => loadRecordings(directory, videos), /scenes do not match/);
    for (const invalid of [null, { version: 1, videos: [null] }]) {
      fs.writeFileSync(file, JSON.stringify(invalid));
      assert.throws(() => loadRecordings(directory, videos), /Unsupported narration manifest/);
    }
  });

  it('validates CLI modes, paths, and video IDs before starting capture', () => {
    assert.equal(parseArgs(['--export-scripts', '--output-dir', 'packet', 'overview']).mode, 'export');
    assert.equal(parseArgs(['--check-narration', '--narration-dir', 'packet']).mode, 'check');
    assert.throws(() => parseArgs(['--export-scripts']), /--output-dir/);
    assert.throws(() => parseArgs(['--export-scripts', '--output-dir']), /requires a directory/);
    assert.throws(() => parseArgs(['--synthetic']), /Unknown option/);
    assert.throws(() => parseArgs(['--export-scripts', '--check-narration']), /not both/);
    assert.throws(() => recordingPlan(['not-a-video']), /Unknown video/);
  });

  it('prints help without starting a browser, creating media, or requiring recordings', () => {
    const result = spawnSync(process.execPath, [path.join(__dirname, '../scripts/build-videos.cjs'), '--help'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /--narration-dir/);
  });

  it('exports through the CLI and reports missing takes with a nonzero exit', t => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-narration-cli-'));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const directory = path.join(root, 'packet');
    const cli = path.join(__dirname, '../scripts/build-videos.cjs');
    const exported = spawnSync(process.execPath, [cli, '--export-scripts', '--output-dir', directory, 'overview'], { encoding: 'utf8' });
    assert.equal(exported.status, 0, exported.stderr);
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'))).videos.length, 1);
    const output = path.join(root, 'draft');
    const failed = spawnSync(process.execPath, [cli, '--narration-dir', directory, '--output-dir', output, 'overview'], { encoding: 'utf8' });
    assert.equal(failed.status, 1);
    assert.match(failed.stderr, /Missing or empty human recording/);
    assert.ok(!fs.existsSync(output), 'must not touch media output when preflight fails');
  });
});
