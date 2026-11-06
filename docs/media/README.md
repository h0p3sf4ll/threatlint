# Documentation media: source and provenance

## Architecture drawings

- `architecture.svg`: shared contracts and separate native-client, Python, Workbench, and CI/Teams runtimes.
- `execution-plan.svg`: independent inspections, upstream dependencies, and bounded parallel execution.
- `data-flow.svg`: Workbench evidence flow, local/remote trust boundaries, report persistence, and authorized operational writes.

The SVGs are editable source, not screenshots or proof of deployed configuration. Their labels
are explained and linked to implementation in [Architecture](../architecture.md). They include
accessible titles/descriptions and are designed for a light documentation canvas.

For local visual QA with Inkscape:

```bash
inkscape docs/media/architecture.svg --export-type=png --export-filename=/tmp/threatlint-architecture.png
inkscape docs/media/data-flow.svg --export-type=png --export-filename=/tmp/threatlint-data-flow.png
inkscape docs/media/execution-plan.svg --export-type=png --export-filename=/tmp/threatlint-execution-plan.png
```

Inspect the exported pixels for clipped labels, overlapping arrows, or illegible text. Do not
commit these temporary exports in addition to the editable SVG unless a consumer needs them.

## Existing recordings and stills

`overview`, `first-review`, `connect-source`, `runtime-scan`, `ask`, `dashboards`, and `ide`
are existing synthetic demonstrations. Their generator is
[`web/scripts/build-videos.cjs`](../../web/scripts/build-videos.cjs). They should not be described
as a fresh capture of a changed interface, a live provider run, or results from a user's source.
The narrated videos retain the status described in [Narration](../narration.md).

## Capture the current threat-model flow

The fixture-based browser check exercises the actual Workbench against a synthetic source
manager and model response, checks the selected revision and supporting-input behavior, and
can save PNGs. It does not authenticate to a provider or review real customer code.

After installing the Workbench dependencies and a supported Playwright Chromium:

```bash
THREATLINT_SCREENSHOTS=docs/media node web/tests/threat-model-browser-smoke.cjs
```

To use an already-installed Chromium, also set `THREATLINT_BROWSER_EXECUTABLE` to its absolute
path. Run from the repository root. Consult the test for the current screenshot filenames.

Only add new screenshot links to README after the command succeeds, the expected files exist,
and someone inspects the actual pixels. Record the branch/commit, test command, fixture source,
and passed checks when handing off refreshed media. A browser startup failure is a capture
blocker, not permission to draw a substitute screenshot or relabel an older image as current.
