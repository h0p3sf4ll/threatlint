# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Threatlint Workbench

The workbench is a single-user, local-first interface for all fourteen Threatlint specialists.
It runs as a browser application or a sandboxed Electron desktop app. Both use the same Node.js
backend, canonical agent definitions, skill registry, provider adapters, and report parser.

## Requirements and first launch

- Node.js **22+** with npm.
- One configured model provider: a running LM Studio-compatible server, Anthropic, or OpenAI.
- Optional: Python **3.9+** with `python-docx` for formatted Word exports.
- For development tests: the Python `dev` extras provide pytest; JavaScript tests use Node's
  built-in runner. Playwright is included as a development dependency for browser/desktop tests.

From the repository root:

```bash
npm --prefix web ci
npm --prefix web run desktop
# Or run the same workbench in a browser:
npm --prefix web start
```

The browser address is <http://127.0.0.1:3000>. Change `PORT` if necessary. The desktop app chooses
its own available loopback port and starts/stops its backend with the application.

### Models and credentials

Open **Model & settings**, select a provider, and enter a model ID actually available to your
account/server. No hard-coded cloud model catalogue is assumed.

- **LM Studio:** load a tool-capable model, start its local server, leave the URL at
  <http://localhost:1234/v1>, and click **Load models**. The model must support OpenAI-compatible
  streamed tool calls for repository inspection. HTTP is restricted to loopback hosts; remote
  compatible servers require HTTPS.
- **False positive review:** *Test → False positive review* reviews one AVIT or a list, one at a time.
  Each AVIT gets its own report, and its own closure or work note. See [avit-integration.md](avit-integration.md).
- **Settings page:** *Settings* in the sidebar is a normal page with **Model provider**, **ServiceNow**
  (instance, OAuth client, AWS CLI read), **Semgrep** (API token) and **Azure DevOps** (PAT) sections,
  each saved separately. ServiceNow, Semgrep and Azure DevOps are required for *False positive review*,
  which shows a setup checklist and does not start until all three are configured.
- **Desktop app:** it trusts the OS certificate store (macOS Keychain / Windows certificate store), so model
  gateways behind corporate TLS inspection work, and it adds your login-shell PATH so `gh`, `git`, `az`, and
  `aws` are found when launched from the Dock or Start menu.
- **Anthropic / OpenAI / Copilot:** choose the provider, and the **Model** dropdown fills with the
  models your credential can use (click **Load models** to refresh). *Enter a model ID manually*
  still accepts any ID. A session-only key typed in the dialog takes priority; otherwise the
  Workbench uses the credential where each tool normally keeps it:

  | Provider | Looked up in order |
  | --- | --- |
  | Anthropic | `ANTHROPIC_API_KEY` → `env` block of `~/.claude/settings.json` (`%USERPROFILE%\.claude\settings.json` on Windows: `ANTHROPIC_API_KEY`, then `ANTHROPIC_AUTH_TOKEN`) → `ANTHROPIC_AUTH_TOKEN`. `ANTHROPIC_BASE_URL` (environment or settings.json) routes model listing and reviews through your gateway. |
  | OpenAI | `OPENAI_API_KEY` → an API key saved by Codex (`codex login --with-api-key`, in `~/.codex/auth.json`). A Codex *ChatGPT-account* sign-in only works inside Codex and is not used. |
  | GitHub Copilot | `COPILOT_GITHUB_TOKEN` → `GH_TOKEN` → `GITHUB_TOKEN` → the GitHub CLI sign-in (`gh auth token`; run `gh auth login` once) |

  Copilot lists only models your plan enables that support `/chat/completions` with tool calls,
  because reviews need streamed tool use. Copilot plan quotas apply: an exhausted quota shows
  HTTP 429. Claude Code's subscription login (macOS Keychain / `~/.claude/.credentials.json`) is
  never read. The UI shows which source is in use, never the value.
- **Remote data consent:** cloud (including Copilot) and remote compatible-model reviews require explicit UI consent.
  Prompts, attached findings, and inspected source/tool results are transmitted to that provider.
- Credentials are never put into browser storage, session history, report metadata, or URLs.
  Non-secret model/provider/URL preferences may be saved. Consent is not persisted across restarts.

The workbench never starts a model scan automatically. Sample report preview is synthetic, labelled,
and requires no provider. Integration tests use deterministic provider fixtures, not paid API calls.

## Review experience

1. Open the source directory. The desktop uses a native picker; the browser accepts a path and
   offers directory browsing. Workspace history is listed in the sidebar.
2. Select **Security baseline**, **Pull request review**, **Find signal in the noise**, or
   **Close the loop**, or build a custom ordered pipeline in the Agent library.
3. Add an optional scope: component, path, commit comparison, finding ID, or precise question.
   A findings-triage workflow needs an attachment, a findings path, or a preceding report.
4. Attach `.sarif`, `.json`, `.md`, or `.txt` scanner/report input (UTF-8; maximum 5 MB).
   The first 100,000 characters are supplied as clearly delimited untrusted evidence; truncation
   is explicitly disclosed. This is **not** a promise that every item in a large scan was reviewed.
5. Run. Agents receive their full mapped skills and use Read/Grep/Glob/read-only inspection tools.
  Each subsequent specialist receives bounded executive and detailed-finding context from preceding reports and
   must independently verify it. The history is not an authoritative proof of a finding.
6. Follow live activity or stop the review. Cancellation aborts model requests; completed reports
   remain available. Connection loss is labelled interrupted, never silently rerun or called success.
7. Read/download completed reports. The finding view filters by severity and disposition while
   retaining the full report and proposed fix text. Missing structured fields produce format warnings.

The Skills view exposes the exact packaged workflow bodies and their agent assignments. The registry
is [the agent-to-skill map](../src/threatlint/data/agent-skills.json). Add a skill there, add its valid
SKILL.md, wire its native discovery entry points, and run the skill/agent tests.

## Professional findings reports

The false-positive reviewer is designed for an engineering handoff, not a verdict spreadsheet:

| Tier | Required content |
| --- | --- |
| Executive | Risk and decision, input accounting, prioritized actions, suggested owner/effort |
| Findings | Original IDs, source revision/provenance, evidence/control trace, disposition, severity, confidence |
| Engineering | Proposed code/config fixes, compatibility notes, regression assertions, acceptance matrix |
| Scanner tuning | Original-rule prerequisites, narrow proposal, ruleid/ok fixtures, blast radius, approval and rollback |

The native agent specification is [the FP reviewer](../src/threatlint/data/agents/appsec-fp-reviewer.md).
A [synthetic example](../web/examples/fp-review.md) is bundled for interface previews.

TRUE POSITIVE / FALSE POSITIVE / AMBIGUOUS is independent of severity/confidence. An unreviewed scan
revision, unseen caller, missing scanner rule, or runtime uncertainty must be disclosed. A verified
false positive does not establish suppression safety. Proposed fixes remain **NOT APPLIED**; proposed
tests and scanner checks are **NOT RUN** unless actual execution evidence exists.

Automatic format checks inspect report headings, explicit fields, evidence-reference shapes,
remediation sections, and acceptance language. They do **not** validate source citations, exploitability,
Semgrep semantics, test outcomes, or coverage preservation. Human engineering/security review is required.

## Storage and security boundary

### Local storage

- Browser runner: the user's home directory under `.threatlint/workbench`, unless
  `THREATLINT_STATE_DIR` specifies another absolute directory.
- Desktop: Electron's per-user application-data directory, in its workbench subdirectory.
- Metadata is atomically persisted; report files live in per-session directories. Keys and uploaded
  scanner attachments are not persisted. Reports contain source evidence and must be treated as
  sensitive local documents. Reports and metadata are not encrypted at rest by the application.
- Source is not modified by analysis. Generated reports are stored outside the inspected repository.
- Removing a source directory does not automatically delete retained reports. Manage retention
  using your local data policy; there is no cloud synchronization or telemetry service.

### Execution controls

- The backend binds loopback only, rejects cross-origin/browser requests and unexpected Host values,
  and checks WebSocket origins. It is not an authenticated multi-user server and must not be
  exposed through a public reverse proxy or port forward.
- Tool commands run without a shell, use an allowlist, and reject mutations, command chaining,
  interpreters, output flags, and common command hooks. Read/Grep/Glob paths are confined to the
  selected repository and reject resolved symlink escapes.
- Shell inspection is defense-in-depth, **not** an operating-system filesystem/process sandbox.
  Git configuration, filesystem races, unusual external tools, and malicious repositories still
  require caution. Use disposable OS/container isolation for untrusted repositories.
- Desktop renderer: sandbox enabled, context isolation enabled, Node integration disabled.
  Narrow IPC permits only native repository/findings selection; arbitrary filesystem/command
  execution is not exposed to the renderer. Outbound renderer requests are blocked.
- Reports/skills render through local `marked` and DOMPurify packages under a restrictive CSP.
  No CDN, font service, or external image fetch is required. Raw provider errors are not treated
  as trusted HTML. Untrusted repository/attachment text remains evidence rather than instructions.
- No automatic exploit execution, secret validation, application patching, or scanner suppression.

### Word export

The converter is bundled, not dependent on a previous global Claude installation. The backend runs
`python3` by default; set `THREATLINT_PYTHON` to an absolute Python executable when needed.
That interpreter must have `python-docx` available. If conversion fails, the Markdown report remains
readable/downloadable and the Word download is omitted. The app does not install Python packages.

## Desktop packaging

```bash
# Build an unpacked application for the current platform
npm --prefix web run desktop:pack

# Produce distribution targets for the current platform
npm --prefix web run desktop:dist
```

Targets are macOS DMG/ZIP, Windows NSIS, and Linux AppImage/DEB. Build on the target OS for normal
distribution workflows. Output is written to the ignored release directory under web.
The app bundles canonical agents, all skills, the registry, report converter, frontend, and production
Node modules. Python and local models are not bundled.

For an offline build using an already installed Electron distribution, from the web directory:

```bash
npm run desktop:pack -- --mac --arm64 -c.mac.identity=null \
  -c.electronDist=node_modules/electron/dist -c.electronVersion=40.10.2
```

The unsigned macOS application bundle has been built and smoke-tested during this change. Signing,
notarization, installer distribution, auto-update infrastructure, and Windows/Linux runtime validation
have **not** been completed. Do not describe the local unsigned bundle as a signed production release.
Use your organization's signing/notarization process before distributing it to other machines.

The ZIP-reader override pins the extractor to a maintained cached version. Revalidate packaging if
Electron/extractor versions change; the override is explicit in the package manifest and lockfile.

## Tests and validation

```bash
# Unit, API, tool-policy, provider-stream, persistence, and pipeline regression tests
npm --prefix web test
python -m pytest tests -q

# Browser E2E (install Playwright's browser once, or use an installed Chromium executable)
npx --prefix web playwright install chromium
npm --prefix web run test:browser

# Example: use locally installed Chrome without a browser download
THREATLINT_BROWSER_EXECUTABLE='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' \
  npm --prefix web run test:browser

# Real Electron startup, agent/skill counts, report preview, and renderer isolation
npm --prefix web run test:desktop
```

Set `THREATLINT_DESKTOP_EXECUTABLE` to a packaged executable to exercise a built app instead of
the development Electron launch. Browser tests create isolated temporary repositories/history and
use deterministic synthetic report fixtures. No live cloud credentials or models are required.

Validated locally: all Python/Node regressions, the browser user journey including cancellation,
credential non-persistence, history and mobile layout, and macOS ARM64 packaged Electron startup.
Model-generated semantic quality and live cloud/local model interoperability still require testing
against the actual chosen provider/model. Prompt improvements and format checks are not quality guarantees.

## Troubleshooting

| Symptom | Next step |
| --- | --- |
| No local models | Load a tool-capable model in LM Studio and start its server; check URL/port |
| API/model error | Check exact model ID, account access, credentials, and provider availability |
| Missing Word button | Check the configured Python executable has `python-docx`; Markdown remains available |
| Input too large | Split the scan by component/rule; inspect explicit unreviewed/truncation limitations |
| Disconnected during a review | Completed reports are retained; incomplete review is not marked successful; reconnect and rerun explicitly |
| Blocked inspection command | Use structured Read/Grep/Glob, or one supported read-only Git command without pipes/redirection |
| History cannot be read | Original metadata is preserved; back it up and resolve invalid/corrupt JSON before restarting |
| macOS warns about unsigned app | Use a locally built app according to your device policy; sign/notarize before distribution |

## One codebase for browser and desktop

`web/desktop/main.cjs` calls `createWorkbench()` from `web/server.js`, listens on a random loopback
port, and loads the same `web/public` UI that the browser runner serves. The desktop app adds only
native file pickers, a sandboxed renderer, and packaging. Every route, agent, view, chart, and video
is the same in both, so a change to `server.js`, `web/lib/`, or `web/public/` is a change to both.
`npm --prefix web run test:browser` and `npm --prefix web run test:desktop` exercise each shell.

The packaged app is kept current with `desktop:dev` (live reload), the optional git hooks
(`npm --prefix web run hooks:install`), `desktop:verify` / `desktop:sync` (build-stamp check), and
the `desktop-build.yml` CI workflow. See the README section *Keeping the desktop app current*.

## Source code managers

**Sources** connects GitHub or Azure DevOps (cloud) with a token you provide:

| Provider | Token | Permissions |
| --- | --- | --- |
| GitHub | Fine-grained PAT, or a GitHub App installation token | Contents: read, Metadata: read |
| Azure DevOps | PAT plus organization name (not a URL) | Code: Read (`vso.code`) |

With a GitHub App saved in **Settings → GitHub** (or by `threatlint github login`), Sources connects to GitHub
on its own as *GitHub App · \<owner\>*. The runner mints the installation token server-side and replaces it
before it expires. See [GitHub App authentication](github-app.md).

Tokens are held in runner memory only and cleared on disconnect or restart. Discovery is GET-only
with pinned, validated DNS, bounded pages, and response-size limits. **Check out & open workspace**
creates a shallow clone with hooks, submodules, and LFS disabled, then opens it as a workspace that
records provider, repository, branch, and commit. GitHub Enterprise Server and Azure DevOps Server
are not supported yet.

## Runtime scanning

See the README section *Runtime scanning and the attack chain* for the auth matrix. Operational
details:

- Paths are explicit, origin-relative, and normalized. No crawling, query strings, or payloads.
- The request budget (default 20, max 100) is shared across all identities. Paths beyond it are
  reported as **not tested** in coverage.
- Only `GET` is sent to the target. The token endpoint and form-login endpoint receive one `POST`
  each when those workflows are selected.
- Manual browser sign-in needs Playwright Chromium on the runner (`npx playwright install chromium`).
  The sign-in browser is closed when you press Finish; only target-origin cookies are kept, for 15
  minutes.
- Exports (JSON, Markdown, HTML) contain observations and request metadata, never credentials.

### Reading the attack chain

Columns run left to right: **Scope & authority → Identity → Entrypoint (request) → Response /
control → Finding observation → Impact hypothesis**. Solid lines are observed; dashed amber lines
lead to impact hypotheses, which are never validated by the scanner. Select a node to see its full
chain from target to impact in the inspector, and tick **Finding chains only** to hide requests that
produced no finding. A `401/403` node is an access control that held.

## Importing a scan report

*Test → Import scan report* takes an **Invicti** (DAST, XML or JSON export) or **MobSF** (mobile,
JSON report) file, up to 5 MB. Drop it on the page or press **Choose file**, leave **Scanner** on
*Auto-detect* (or pick one), and optionally choose a **workspace** so triage can read the matching
source, and enter the **AVIT number** (AVIT plus 7 to 15 digits).

**Import and triage** shows progress as *Queued → Parsing → Triaging → Done*. The result shows
the scan title and target, true-positive / false-positive / ambiguous counts, and a findings table
(severity, disposition, confidence, location). The saved report appears in *Findings* with a
descriptive title: **Open report** opens it there, and **Markdown** / **Word** download it.

The file is parsed on this machine. Findings go only to the model provider chosen in Settings, and
to ServiceNow only when you press **Post to ServiceNow**. That asks for the AVIT and confirmation
first, then attaches the Word report, closes false positives as *Closed / False Positive* with the
Threatlint comment, and adds work notes to true positives and ambiguous findings. It lists the
actions ServiceNow applied, or the error (for example, an AVIT the integration account cannot read).
*Previous imports* lists earlier imports, newest first. Endpoints: `POST /api/scan-import`,
`GET /api/scan-import[/:id]`, `POST /api/scan-import/:id/servicenow`.

## In-app help

Every key control has a **?** tooltip. **Learn & videos** (or `?` on the keyboard) has the narrated
video library, task guides, and a glossary. Videos live in `web/public/media`, so they play offline
in both the browser and the desktop app. Rebuild them after UI changes with
`npm --prefix web run videos`; see `web/scripts/build-videos.cjs` for requirements.

## Metrics

See [dashboards.md](dashboards.md).


## Developer flow

The sidebar follows the order you work in:

1. **Test**: *Review code* (playbooks and pipeline), *Connect source* (GitHub / Azure DevOps
   checkout), *Scan running app* (authenticated runtime scan), *False positive review* (AVITs),
   and *Import scan report* (Invicti / MobSF files).
2. **Fix**: *Findings* (reports with file:line, fix, and test) and *Ask Threatlint*.
3. **Track**: *Metrics* and dashboards.
4. **Reference**: *Agents*, *Skills*, and *Learn & videos*.

A four-step checklist (open code → choose model → run → fix and ask) sits at the top of *Review
code* until you've done each step once.

## Ask Threatlint

Conversations run over the same runner socket as reviews (`chat` / `chat_cancel` actions) and use
the model chosen in Model & settings. Each conversation is about the workspace, a report, a single
finding, or a runtime scan; that context is sent to the model once, as delimited untrusted data,
and the assistant reads the repository with the read-only Read / Grep / Glob / Bash tools (24
tool rounds per answer). Threads persist in `conversations.json` beside the workbench history
(text only, never keys) and keep the last 20 turns within a 60,000-character budget. A failed or
stopped answer is discarded so history never holds an unanswered turn.

## Code layout

| Module | Responsibility |
| --- | --- |
| `server.js` | Composition root: builds the store and services, registers routes, attaches the socket |
| `lib/http.cjs` | Loopback guard, security headers, `handle()` error mapping, `HttpError` |
| `lib/routes/*.cjs` | One module per area: workspace, sources, runtime, insights (metrics, dashboards, help, conversations) |
| `lib/socket.cjs` | WebSocket action table (`run_pipeline`, `cancel`, `chat`, `chat_cancel`) |
| `lib/pipeline.cjs` | Review validation, prompt building, `runModel()` shared by reviews and chat |
| `lib/chat.cjs` | Conversation store, context resolution, multi-turn history |
| `lib/report-writer.cjs` | Markdown/Word persistence and report metadata |
| `lib/providers.cjs` | Claude and OpenAI-compatible streaming with tool use |
| `lib/scm.cjs`, `lib/runtime.cjs`, `lib/metrics.cjs` | Source managers, runtime scanner, metrics |
| `public/app.js` | Workspace, pipeline, reports; publishes `threatlint:context` to other view modules |
| `public/operations.js`, `charts.js`, `insights.js`, `chat.js` | Sources & runtime, charts, metrics & help, conversations |

View modules talk only through DOM events (`threatlint:navigate`, `threatlint:context`,
`threatlint:ask`, `threatlint:workspace`, `threatlint:runtime-evidence`), never shared globals.
