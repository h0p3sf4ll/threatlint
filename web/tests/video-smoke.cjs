'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { main, recordingPlan } = require('../scripts/build-videos.cjs');
const { exportPacket, loadRecordings, probeAudio } = require('../scripts/video-narration.cjs');

function publishedHashes() {
  return ['web/public/media/overview.mp4', 'web/public/media/overview.png', 'docs/media/overview.png', 'docs/media/overview.gif']
    .map(relative => {
      const file = path.resolve(__dirname, '../..', relative);
      return fs.existsSync(file) ? createHash('sha256').update(fs.readFileSync(file)).digest('hex') : null;
    });
}

async function smoke() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-video-smoke-'));
  const before = publishedHashes();
  try {
    const packet = path.join(root, 'packet');
    const output = path.join(root, 'draft');
    const videos = recordingPlan(['overview']);
    const manifest = exportPacket(packet, videos);
    const fixture = path.join(root, 'test-tone.wav');
    execFileSync('ffmpeg', ['-hide_banner', '-loglevel', 'error', '-f', 'lavfi', '-i', 'sine=frequency=440:sample_rate=48000', '-t', '1', '-c:a', 'pcm_s24le', fixture]);
    for (const scene of manifest.videos[0].scenes) fs.copyFileSync(fixture, path.join(packet, scene.file));
    const clips = loadRecordings(packet, videos).get('overview');
    assert.ok(clips.every(clip => Math.abs(clip.seconds - 1) < 0.001));

    console.log('Rendering a disposable test-tone fixture, not a human voiceover.');
    await main(['--narration-dir', packet, '--output-dir', output, 'overview']);
    const metadata = JSON.parse(execFileSync('ffprobe', ['-v', 'error', '-show_streams', '-show_format', '-of', 'json', path.join(output, 'overview.mp4')], { encoding: 'utf8' }));
    const audio = metadata.streams.find(stream => stream.codec_type === 'audio');
    const video = metadata.streams.find(stream => stream.codec_type === 'video');
    assert.equal(audio.codec_name, 'aac');
    assert.equal(audio.sample_rate, '48000');
    assert.equal(video.width, 1440);
    assert.equal(video.height, 900);
    const expected = clips.reduce((sum, clip) => sum + clip.seconds + 0.7, 0);
    assert.ok(Math.abs(Number(metadata.format.duration) - expected) < 0.5, 'scene timing must follow take duration, allowing frame/AAC rounding');
    for (const file of ['overview.png', 'previews/overview.png', 'previews/overview.gif']) assert.ok(fs.statSync(path.join(output, file)).size > 0);

    const invalid = path.join(root, 'invalid.wav');
    fs.writeFileSync(invalid, 'not a WAV recording');
    assert.throws(() => probeAudio(invalid), /Cannot read WAV recording/);
    assert.deepEqual(publishedHashes(), before, 'draft rendering must not change published assets');
    console.log(`PASS: ${clips.length} scenes, ${Number(metadata.format.duration).toFixed(2)}s, AAC 48 kHz, posters/GIF, invalid-audio rejection; published assets unchanged.`);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

smoke().catch(error => { console.error(error); process.exitCode = 1; });
