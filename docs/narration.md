# A voice worth listening to

A useful walkthrough should feel like a colleague showing you the next step,
not a machine reading a feature list.

**Current status (2026-11-20):** the seven bundled tutorials pair original screen
footage with the saved narration and timed captions
from the [Threatlint Descript project](https://web.descript.com/0cc8bb8f-1d1c-4b0d-bb1c-947fb9cefd90).
They contain synthetic narration, including partially regenerated Descript voiceovers.
The editing job exhausted its AI credits before
voice consistency and final editorial review were completed. Additional lessons
were planned but not created. Do not describe this library as human-recorded or
as a completed voice replacement.

The raw Descript exports contained large overlays that hid the screen actions.
The bundled clips instead use the original scene frames from commit
`70e9802d8bfe9b280d76d18dde81827718562ed9`, timed to the updated narration.
The original caption areas are replaced with captions from Descript's SRT exports.
Only the saved Descript audio is included; it is copied without re-encoding or
mixing in the original source audio.

The rebuilt clips replace the existing MP4 filenames in `web/public/media`, so the
Workbench, desktop package, and documentation video links use the same bundled
files without contacting Descript during playback. Posters and silent previews
are extracted from those rebuilt clips. To update them again, export the corresponding
compositions from Descript and inspect the visuals, captions, timing, and narration
before replacing each MP4 and its matching poster/preview. Do not copy the raw
exports over the repaired visuals without checking for obscuring overlays.
Keep temporary signed download URLs out of Git.

The optional recording workflow below is prepared for a **human female narrator**:
warm, clear, conversational, and comfortable with technical language. The local
builder does not generate text-to-speech or clone voices. Its source scripts do
not reproduce the Descript timeline edits; running it without `--output-dir`
replaces those bundled clips. Use a separate draft directory when trying this workflow.

## 1. Hand off a recording packet

From the repository root, with Node 22 or newer:

```bash
npm --prefix web run videos:scripts -- --output-dir /tmp/threatlint-narration
```

Choose a new, empty directory outside the checkout. Export never overwrites an
existing packet. Export needs neither a browser nor ffmpeg.

The packet contains:

| Path | Purpose |
| --- | --- |
| `README.md` | Performance brief, pronunciation, and recording checklist |
| `scripts/<video-id>.md` | Spoken text, scene order, and exact take filenames |
| `manifest.json` | Script revision matching; leave it unchanged |
| `audio/<video-id>/01.wav` | Where the narrator supplies each recorded take |

The seven video IDs are `overview`, `first-review`, `ask`, `connect-source`,
`runtime-scan`, `dashboards`, and `ide`. Append IDs to any command to work on a
subset. Start with `overview` as the audition before recording the whole library.
Keep the packet and original takes out of source control unless storage and
publication rights have been agreed.

## 2. Record a person, not a persona

- Cast a human female performer and agree on recording and publication rights.
- Speak to one colleague. Use natural emphasis, breaths, and pauses.
- Avoid an announcer voice, exaggerated cheerfulness, or forced high pitch.
- Record one WAV per scene, preferably **48 kHz, 24-bit mono**. Mono and stereo
  WAV recordings are accepted; use a consistent microphone setup.
- Leave a little room around each take. Do not add music, reverb, pitch shifts,
  speed changes, or aggressive noise reduction.
- Read the supplied text. If wording needs changing, update the source script
  and export a fresh packet before recording that revision.

The source of truth is the scene text in
[the video builder](../web/scripts/build-videos.cjs). Keep spoken text and the
visual action together so a later wording change cannot silently reuse an old take.

## 3. Check and render a draft

Audio validation needs `ffprobe`; rendering also needs `ffmpeg` and Playwright's
Chromium. Install the existing Workbench dependencies if not already present:

```bash
npm --prefix web ci
cd web
npx playwright install chromium
cd ..
```

For an existing Chromium installation, set `THREATLINT_BROWSER_EXECUTABLE` to its
executable path. Developers can check the rendering pipeline with
`npm --prefix web run test:videos`; it uses a disposable test tone, not narration,
and verifies that published assets remain unchanged.

Then validate the takes and render outside the published media directories:

```bash
npm --prefix web run videos:check -- \
  --narration-dir /tmp/threatlint-narration overview
npm --prefix web run videos -- \
  --narration-dir /tmp/threatlint-narration \
  --output-dir /tmp/threatlint-narration-draft overview
```

Open the draft's `overview.mp4`. Posters and silent GIF previews are also
generated, with README previews under `previews/`.

The builder rejects missing, empty, unreadable, mismatched, or stale recordings
before starting a browser or touching media output. Each scene follows its take's
actual duration, plus a short pause. Loudness normalization targets -16 LUFS and
-1.5 dB true peak; it does not change speaking speed or pitch.

**A successful check verifies files and script matching, not the speaker.**
It cannot establish gender, human origin, recording rights, spoken accuracy, or
natural delivery. Silence can be valid audio metadata: listen to every take.

## 4. Approve with your ears, then publish

Listen on headphones and ordinary laptop speakers:

- Does this sound like a person helping, rather than reading a brochure?
- Are pacing, technical terms, and pauses clear without feeling rushed?
- Are there distracting breaths, clicks, clipping, room noise, or abrupt edits?
- Does every scene say the approved text and match the screen?
- Has the performer approved the intended use?

After approval, omit `--output-dir` to replace the selected published assets:

```bash
npm --prefix web run videos -- \
  --narration-dir /tmp/threatlint-narration overview
```

This writes MP4s and posters to [the Workbench media folder](../web/public/media/)
and silent previews to [the documentation media folder](media/). Review the media
diff and follow [the media storage guidance](development.md#media-and-git-lfs)
before committing. Omit the video ID only when all seven recordings are approved.

## When a check stops you

| Message | Next action |
| --- | --- |
| Destination is not empty | Export to a new directory; preserve existing takes |
| Missing or empty human recording | Record the scene at the displayed WAV path |
| Script changed / scenes do not match | Export a fresh packet; re-record changed scenes and copy only unchanged takes |
| Cannot read WAV / invalid duration | Re-export the take as a valid mono or stereo WAV |
| ffprobe is required | Install ffmpeg using your platform's package manager |

Do not edit the manifest to make stale recordings pass.
