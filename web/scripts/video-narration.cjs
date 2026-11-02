'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const BRIEF = `# Human narration recording brief

## Voice and delivery

Cast a human female narrator with a warm, clear, conversational delivery.
Speak to one colleague, not an auditorium. Use natural emphasis and breathing;
avoid a sales-announcer cadence, forced cheerfulness, or a flattened read.
Do not use text-to-speech, voice cloning, pitch shifting, or speed changes.

Record a short overview audition and approve it by listening before recording
the whole library. Confirm the performer's consent and publication rights.
This workflow cannot determine whether a recording is human or licensed.

## Recording and handoff

- Read each scene exactly as supplied; discuss wording changes before recording.
- Record one PCM WAV per scene, preferably 48 kHz, 24-bit mono.
- Leave a little room before and after each take; keep natural pauses.
- Use a quiet, non-reverberant room, a consistent microphone position, and no music.
- Avoid clipping, heavy noise reduction, exaggerated compression, and reverb.
- Use the exact audio paths in the scene scripts. Do not edit manifest.json.
- Pronounce Threatlint as "thret-lint", API as "A P I", and CLI as "C L I".

The renderer follows each recording's actual duration, with a short pause between
scenes. It normalizes loudness without changing speaking speed or pitch.

## Listen before publishing

Check warmth, natural phrasing, intelligibility, pacing, breaths, clicks, clipping,
room noise, and correct technical terms. Review the rendered draft with sound.
No automated metadata check can replace this listening pass.
`;

function parseArgs(argv) {
  const options = { mode: 'render', ids: [], narrationDir: '', outputDir: '' };
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--help') { options.help = true; continue; }
    if (arg === '--export-scripts' || arg === '--check-narration') {
      if (options.mode !== 'render') throw new Error('Choose either script export or narration checking, not both.');
      options.mode = arg === '--export-scripts' ? 'export' : 'check';
    } else if (arg === '--narration-dir' || arg === '--output-dir') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) throw new Error(`${arg} requires a directory.`);
      options[arg === '--narration-dir' ? 'narrationDir' : 'outputDir'] = path.resolve(value);
    } else if (arg.startsWith('-')) throw new Error(`Unknown option: ${arg}`);
    else options.ids.push(arg);
  }
  if (!options.help && options.mode === 'export' && !options.outputDir) throw new Error('Script export requires --output-dir DIR.');
  if (!options.help && options.mode !== 'export' && !options.narrationDir) {
    throw new Error('Human recordings are required. Export scripts with npm run videos:scripts -- --output-dir DIR, then supply --narration-dir DIR. Synthetic speech is not a fallback.');
  }
  return options;
}

function sceneFile(id, index) {
  return `audio/${id}/${String(index + 1).padStart(2, '0')}.wav`;
}

function exportPacket(directory, videos) {
  if (fs.existsSync(directory) && fs.readdirSync(directory).length) {
    throw new Error(`Recording packet destination is not empty: ${directory}. Choose a new directory; existing scripts and recordings will not be overwritten.`);
  }
  fs.mkdirSync(path.join(directory, 'scripts'), { recursive: true });
  const manifest = { version: 1, videos: videos.map(video => ({
    id: video.id, title: video.title,
    scenes: video.scenes.map((scene, index) => ({ file: sceneFile(video.id, index), text: scene.say })),
  })) };
  for (const video of manifest.videos) {
    fs.mkdirSync(path.join(directory, 'audio', video.id), { recursive: true });
    const script = [`# ${video.title}`, '', 'Human female narrator. Follow the recording brief in README.md.', '',
      ...video.scenes.flatMap((scene, index) => [`## Scene ${index + 1}`, '', `Save as: \`${scene.file}\``, '', scene.text, ''])].join('\n');
    fs.writeFileSync(path.join(directory, 'scripts', `${video.id}.md`), script);
  }
  fs.writeFileSync(path.join(directory, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  fs.writeFileSync(path.join(directory, 'README.md'), BRIEF + '\n## Scene scripts\n\n' +
    manifest.videos.map(video => `- [${video.title}](scripts/${video.id}.md) (${video.scenes.length} takes)`).join('\n') + '\n');
  return manifest;
}

function probeAudio(file, { run = execFileSync } = {}) {
  let raw;
  try {
    raw = run('ffprobe', ['-v', 'error', '-show_entries', 'stream=codec_type,sample_rate,channels:format=duration,format_name', '-of', 'json', file], { encoding: 'utf8' });
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('ffprobe is required to validate recorded audio. Install ffmpeg before checking or rendering narration.');
    throw new Error(`Cannot read WAV recording ${file}: ${error.stderr?.toString().trim() || error.message}`);
  }
  const metadata = JSON.parse(raw);
  const stream = metadata.streams?.find(item => item.codec_type === 'audio');
  const seconds = Number(metadata.format?.duration);
  if (metadata.format?.format_name !== 'wav' || !stream || ![1, 2].includes(stream.channels) ||
      !(Number(stream.sample_rate) > 0) || !Number.isFinite(seconds) || seconds <= 0) {
    throw new Error(`Recording must be a non-empty mono or stereo WAV with a valid duration: ${file}`);
  }
  return seconds;
}

function loadRecordings(directory, videos, { probe = probeAudio } = {}) {
  const manifest = JSON.parse(fs.readFileSync(path.join(directory, 'manifest.json'), 'utf8'));
  if (!manifest || manifest.version !== 1 || !Array.isArray(manifest.videos) ||
      manifest.videos.some(video => !video || typeof video.id !== 'string')) {
    throw new Error('Unsupported narration manifest. Export a fresh recording packet.');
  }
  const recordings = new Map();
  for (const video of videos) {
    const matches = manifest.videos.filter(item => item.id === video.id);
    const saved = matches[0];
    if (matches.length !== 1 || !Array.isArray(saved.scenes) || saved.scenes.length !== video.scenes.length) {
      throw new Error(`Narration scenes do not match ${video.id}. Export a fresh recording packet.`);
    }
    const clips = video.scenes.map((scene, index) => {
      const entry = saved.scenes[index];
      const relative = sceneFile(video.id, index);
      if (entry?.file !== relative || entry.text !== scene.say) {
        throw new Error(`Narration script changed: ${video.id}, scene ${index + 1}. Export a fresh packet and re-record the changed take.`);
      }
      const file = path.join(directory, relative);
      if (!fs.existsSync(file) || !fs.statSync(file).isFile() || !fs.statSync(file).size) {
        throw new Error(`Missing or empty human recording: ${file}. Record the matching scene; synthetic speech will not be substituted.`);
      }
      const seconds = probe(file);
      if (!Number.isFinite(seconds) || seconds <= 0) throw new Error(`Invalid recording duration: ${file}`);
      return { file, seconds };
    });
    recordings.set(video.id, clips);
  }
  return recordings;
}

module.exports = { parseArgs, exportPacket, loadRecordings, probeAudio };
