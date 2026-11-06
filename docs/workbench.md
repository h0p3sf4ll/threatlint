# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Threatlint Workbench

Turn a security question into an engineering decision: inspect the source, read the evidence,
and leave with a proposed fix and regression assertions. The Workbench brings Threatlint's
specialists, scanner triage, runtime observations, and reports into one single-user interface.
Browser and Electron desktop use the same local Node.js backend and agent definitions.

## Requirements and first launch

You need Node.js **22+** and npm. A model provider is needed for reviews, but not for the synthetic
report preview. Word export also needs Python **3.9+** with `python-docx`.

1. From the repository root, install the Workbench dependencies and start it:

   ```bash
   npm --prefix web ci
   npm --prefix web start
   # Desktop instead:
   npm --prefix web run desktop
   ```

2. Open <http://127.0.0.1:3000> in browser mode. Use `PORT` to change it. Desktop selects an
   available loopback port and manages its backend.
3. Choose **See a sample findings report** to explore the labelled synthetic report without a
   model or credentials. **Expected result:** a findings view with evidence and proposed actions,
   not a scan of your code.
4. Configure a model below, then follow [Review experience](#review-experience) for your first
   source-grounded review. No model scan starts automatically.

### Models and credentials

Open **Settings → Model provider**, select a provider, and **Load models** where available. Choose an available
tool-capable model; manual model IDs are also accepted. Codex uses its built-in default model unless you enter an override.
For **Amazon Bedrock**, enter the exact Claude model or inference profile ID manually and
choose the AWS region; the model picker does not query Bedrock for available models.

| Provider | Setup and credential lookup |
| --- | --- |
| LM Studio / compatible | Load a model supporting OpenAI-compatible streamed tool calls and start the server; default URL `http://localhost:1234/v1`. Remote hosts require HTTPS; HTTP is loopback-only. |
| Anthropic | Session key → `ANTHROPIC_API_KEY` → `env` in `~/.claude/settings.json` (`ANTHROPIC_API_KEY`, then `ANTHROPIC_AUTH_TOKEN`) → `ANTHROPIC_AUTH_TOKEN`. `ANTHROPIC_BASE_URL`, from environment or settings, supports a gateway. |
| Claude Code | Your Claude Code login: install Claude Code and run `claude` once to sign in. No key. Agents run through `claude -p` in restricted, read-only mode (see [setup](setup.md#cloud-providers)). |
| Amazon Bedrock | Session key → `AWS_BEARER_TOKEN_BEDROCK` → `BEDROCK_API_KEY` → those names in `env` in `~/.claude/settings.json`. Uses a Bedrock API key with the regional Messages endpoint. Enter the exact Claude model/profile ID; no Anthropic model default is applied. Region: Settings → `AWS_REGION` → `AWS_DEFAULT_REGION` → Claude settings → `us-east-1`. IAM access keys and AWS SSO are not used by this provider. |
| Daybreak Blue · OpenAI | Session key → `OPENAI_API_KEY` → API key in Codex's API-key login file → your signed-in Codex CLI. With an API key, uses `gpt-6-sol` with the `daybreak_blue` access program through the Responses API. Without an API key, uses your Codex login with `gpt-6-sol` and Daybreak enabled in an ephemeral, read-only run. Settings shows the detected connection; Daybreak approval is required on that account or API project and is checked by OpenAI when the run starts. |
| Daybreak Blue · Amazon Bedrock | Session key → `AWS_BEARER_TOKEN_BEDROCK` → `BEDROCK_API_KEY` → those names in `env` in `~/.claude/settings.json`. Requires approved model access in `us-east-2`. Uses `openai.gpt-daybreak-blue-5.6-sol` through Bedrock Mantle's Responses API. |
| OpenAI | Session key → `OPENAI_API_KEY` → API key in Codex's API-key login file (`$CODEX_HOME/auth.json` or `~/.codex/auth.json`). A ChatGPT-account sign-in does not supply an OpenAI API key. |
| Codex | Your signed-in Codex CLI: run `codex login` first. No API key or explicit model is required. Agents use an ephemeral `codex exec` run with a read-only sandbox and isolated user config, so an unset model uses Codex's built-in default. Threatlint does not read Codex OAuth tokens. Select **Use Daybreak Blue** only if your account has approved access; this selects `gpt-6-sol` by default for that run. |
| GitHub Copilot | Session token → `COPILOT_GITHUB_TOKEN` → `GH_TOKEN` → `GITHUB_TOKEN` → `gh auth token`. Run `gh auth login` first if needed. |

On Windows, `~` means `%USERPROFILE%`. The Workbench never reads Claude Code's or Codex's OAuth credentials;
those CLI providers sign themselves in. Codex receives only its login location and basic operating-system/network environment,
so other Threatlint integration secrets are not inherited by its subprocess. Its sandbox keeps repository inspection read-only.
Copilot lists plan-enabled models supporting tool calls and `/chat/completions`;
account quotas still apply.

With Anthropic, **Threatlint default** follows the runner's review/chat model policy. An explicit
model overrides both; `THREATLINT_SCAN_MODEL` / `THREATLINT_GENERAL_MODEL` or `scanModel` /
`generalModel` in `~/.threatlint/org.json` change the defaults. See [Setup](setup.md).

**Before sending source:** cloud providers, Copilot, and remote compatible servers require explicit
UI consent. Prompts, attached findings, and inspected source/tool results go to that provider.
**Save model settings** stores the selected provider, each provider's model, Codex Daybreak option,
Bedrock region, and local model-server URL in the Workbench's local settings. These choices restore
after exiting and reopening the desktop app, including when its local port changes. Session model
keys are not saved to browser storage, settings, reports, or history; consent does not survive a restart.

Integration credentials are different: **Settings** saves ServiceNow, Semgrep, Azure DevOps,
GitHub App, DefectDojo, and SonarQube configuration through their respective setup flows.
Do not assume those saved credentials are session-only. Desktop uses the OS certificate store
and adds the login-shell PATH so installed `gh`, `git`, `az`, and `aws` commands can be found.

## Review experience

1. **Open code.** Choose a local source directory, or [connect a source manager](#source-code-managers).
   Desktop has a native picker; browser mode supports path entry and browsing.
2. **Choose the decision.** Select **Model a system**, **Security baseline**, **Pull request review**,
   **Find signal in the noise**, **Close the loop**, or an ordered custom pipeline.
3. **Narrow the question.** For example: “Review the working-tree diff for tenant authorization
   changes.” Add a component, path, comparison, or finding ID when useful.
4. **Supply evidence if triaging.** Attach UTF-8 `.sarif`, `.json`, `.md`, or `.txt` input,
   supply a findings path, or use a preceding report. Attachments are limited to **5 MB**;
   only the first **100,000 characters** enter the prompt. Truncation must be disclosed.
   Pipeline Findings triage also requires Semgrep Community Edition on PATH (`semgrep --version`).
5. **Add supporting documents for a threat model (optional).** Press **Add supporting docs** and choose
   diagrams, design documents, specs, or images. See [Design inputs](#design-inputs) for what is read.
6. **Run and inspect.** Specialists use mapped skills and read-only inspection tools. Dependent
   specialists receive bounded upstream-report context, which they must independently verify.
   Independent specialists can overlap; see [execution controls](architecture.md#execution-controls).
7. **Use the report.** Filter findings by severity/disposition, inspect the full evidence and
   proposed fix, then download Markdown or Word. Missing fields produce format warnings.

**Expected result:** a saved advisory report—not applied code, a security approval, or proof every
finding was reviewed. **Stop** cancels model requests; completed reports remain. A lost connection
is labelled interrupted and does not silently rerun. Next: [read and act on reports](reports.md).

### Model a system from source and design

1. Choose **Model a system** to select the threat-model specialist.
2. In **Repository & branch**, press **Select repo / branch**. Connect an authorized GitHub or
   Azure DevOps source, select its repository and branch, then choose **Check out & open workspace**.
   A local folder is also supported; check out the intended branch yourself before review.
3. Confirm the repository, branch, and commit displayed in the review. Connected source checkouts
   verify the selected branch's advertised commit, then detach that commit. If the branch moves
   during checkout, select it again; Threatlint does not silently review a different commit.
4. In **Supporting documentation**, press **Add supporting docs** and choose the design artifacts.
   Wait for extraction to finish and inspect the file list. Add a scope question such as
   “Compare tenant isolation in this design with the implemented request path.”
5. Confirm the selected model/provider and the permission to send it that evidence, then run.
   A document upload must finish before the run starts; supporting inputs cannot be replaced
   while the active review uses them.
6. Inspect the report for implemented controls, design/source disagreements, assumptions, and
   tests still marked **NOT RUN**. A document's assertion is not proof of an implemented control.

The host records source provenance and a supporting-file manifest with content SHA-256 hashes
when that information is available. Hashes identify uploaded bytes, not document truth or user
approval. Locally opened folders do not acquire remote-source provenance automatically, and
local edits during a review can still affect inspected source. Use a stable checkout for a
repeatable comparison.

The visible activity stream is bounded to 500 entries and 200,000 characters, with additional
per-entry truncation. Earlier activity can be omitted as a review grows; use saved final reports
rather than treating the on-screen activity log as a complete audit trail.

### Design inputs

A threat model is only as good as its picture of the system. Design inputs give the specialists the
intended architecture, and the source code shows what was actually built. They report where the two
disagree (**design drift**), such as an admin API drawn inside the authenticated zone whose route has no
authentication check. Findings cite both sides, for example `context.drawio › Admin API` and `server.js:5`.

| Input | What the agents receive |
| --- | --- |
| draw.io / diagrams.net (`.drawio`, plain or compressed) | Each page's trust boundaries and groups, components (with their container), and labelled flows |
| OWASP Threat Dragon (`.json`) | Actors, processes, stores, flows, boundaries, and the threats and mitigations already recorded, which are re-verified rather than copied |
| Microsoft Threat Modeling Tool (`.tm7`), Visio (`.vsdx`), SVG | The text labels in the model or drawing |
| Mermaid, PlantUML, Graphviz, D2, Structurizr DSL, C4 | The diagram source |
| OpenAPI / Swagger (`.json`) | Every operation with its security requirement; public operations are marked `none (public)`. YAML specs are passed as text |
| PDF, Word (`.docx`), PowerPoint (`.pptx`), Markdown, AsciiDoc, reStructuredText, HTML, text | The document text |
| PNG, JPEG, GIF, WebP | The image itself, for whiteboard photos and exported diagrams. With **Claude Code** the image is a file it opens with its Read tool |
| Source code, Terraform, YAML, and other text | The file contents, alongside the repository |

**Limits:** up to **20 files**, **25 MB** in total, **10 MB** per file, and **8 images** (5 MB each). Each
document contributes up to **60,000 characters** and all documents up to **200,000**. Any truncation is
stated in the prompt, so reports must not claim full coverage. Files are read when you add them, so the
list shows what was understood from each one before you run. Bundles stay in memory for four hours and
are never written to disk.

Design inputs are **untrusted evidence**. XML is parsed without DTDs or entities, Office files are
size-capped, nothing is executed, and the prompt fences each document as data, never instructions. Every
specialist in the pipeline receives them, and the threat modeler also looks for design artifacts already
in the repository (`docs/`, ADRs, `*.drawio`, `*.mmd`, `*.puml`, OpenAPI specs).

### Choose parallel or sequential review

Use **Execution → Auto · dependency-aware** for independent inspections with a bounded
parallel limit (default 3, maximum 8). Order report-consuming specialists after the evidence
they need. **Sequential · one at a time** preserves the earlier full-chain behavior. A failed
prerequisite is shown as a skipped dependent review, not a clean report. See the
[execution controls](architecture.md#execution-controls) for dependency rules, process-wide
budgets, error behavior, and API configuration.

## Professional findings reports

The findings-triage specialist produces a handoff, not just a verdict:

| Section | What to use |
| --- | --- |
| Executive | Decision, input accounting, priorities, suggested owner and effort |
| Findings | Original IDs, revision/provenance, evidence, disposition, severity, confidence |
| Engineering | Proposed fixes, compatibility notes, regression assertions, acceptance criteria |
| Scanner tuning | Rule prerequisites, narrow proposal, fixtures, blast radius, approval and rollback |

**TRUE POSITIVE / FALSE POSITIVE** is separate from severity and confidence. If FALSE POSITIVE
cannot be proved beyond reasonable doubt, the finding stays open as a conservative TRUE POSITIVE.
Missing source revisions, callers, rules, or runtime evidence remain explicit limits; this
classification is not a verified exploit. A false-positive
verdict does not authorize suppression. Fixes are **NOT APPLIED** and suggested tests **NOT RUN**
unless actual execution evidence is recorded.

Format checks assess structure, not citation accuracy, exploitability, rule semantics, or test
success. Human review is required. See the [synthetic example](../web/examples/fp-review.md) and
[canonical reviewer](../src/threatlint/data/agents/appsec-fp-reviewer.md).

For ServiceNow items, **Test → Finding triage** accepts AVITs, SCTASKs, and ISSTs in any mix
and reviews AVITs one at a time. A SCTASK expands into the AVITs named in its description; an ISST
expands into the AVITs on its exact repository and branch. A false positive is closed on its AVIT
only (with the Semgrep rule tuned); a true-positive report is attached to its AVIT and, when the
AVIT came from an ISST, to the ISST as well. A SCTASK is closed once all its AVITs are decided;
Threatlint never closes an ISST — true positives are left open for remediation. Its setup checklist
requires ServiceNow OAuth, Semgrep, and Azure DevOps credentials. Configure them in Settings before
starting; use the [AVIT guide](avit-integration.md) for closure and external-write behavior.

## Storage and security boundary

### Local storage

| Data | Location / lifetime |
| --- | --- |
| Browser reports and history | `~/.threatlint/workbench`, or absolute `THREATLINT_STATE_DIR` |
| Desktop reports and history | Electron's per-user application-data directory, under `workbench` |
| Conversations / dashboards | `conversations.json` / `dashboards.json` beside history |
| Session model keys / review attachments | Not persisted in review history |

Reports are stored outside the inspected repository. Reports and conversation text can contain
source evidence; they are **not application-encrypted at rest**. Removing a source directory does
not delete retained reports. Apply your local retention policy; there is no cloud history sync.

### Execution controls

- **Local, not multi-user:** loopback binding, Host/origin checks, and WebSocket origin checks.
  Do not expose the runner through a public proxy or port forward; it has no multi-user authentication.
- **Analysis, not patching:** inspection commands use argument arrays and an allowlist; resolved
  Read/Grep/Glob paths are repository-confined. Mutations, shell chaining, interpreters, output
  flags, and common command hooks are rejected.
- **Not an OS sandbox:** filesystem races, Git configuration, and external tools still matter.
  Use disposable OS/container isolation for untrusted repositories.
- **Desktop renderer:** sandboxed, context-isolated, no Node integration or arbitrary command IPC.
  Outbound renderer requests are blocked. Reports use local rendering libraries, DOMPurify, and CSP.
- **Separate write boundary:** review agents do not patch code, validate secrets, execute exploits,
  or suppress scanner findings. Explicit integration post/resolve actions can change external
  systems; read their confirmation and the relevant integration guide.

### Word export

The bundled converter uses `python3`, or the absolute interpreter set by `THREATLINT_PYTHON`.
That interpreter must already have `python-docx`; the app does not install it. Conversion failure
leaves Markdown available and omits the Word download.

## Source code managers

1. Open **Sources**, choose GitHub or Azure DevOps cloud, and connect:

   | Provider | Minimum read access |
   | --- | --- |
   | GitHub fine-grained PAT / App installation token | Contents: read; Metadata: read |
   | Azure DevOps PAT + organization slug, not URL | Code: Read (`vso.code`) |

2. Select a discovered repository and branch.
3. Choose **Check out & open workspace**.

**Expected result:** a shallow local clone with provider, repository, branch, and commit recorded.
Hooks, submodules, and LFS are disabled. Discovery is GET-only with validated/pinned DNS and bounded
responses. Connection tokens stay in memory and clear on disconnect/restart; a successful checkout
can remain on disk and contains source.

A saved [GitHub App](github-app.md) connects automatically and refreshes installation tokens.
Source browsing does not support GitHub Enterprise Server or Azure DevOps Server.

Once at least one source is connected, the Connect panel shows a **n CONNECTED** badge and the button
becomes **Add another connection**; the loading indicator while a source or its repositories load is a
spinner. A saved source that could not be used (an expired or invalid Azure DevOps PAT, or a GitHub
App token that could not be minted) stays listed under **Connected accounts** marked *not connected*
with the reason (for example *credential rejected or expired*) and a **Reconnect** action, rather than
silently disappearing.

## Runtime scanning

Observe a running app only when you have authority to test it:

1. Open **Scan running app** and enter the target, authorization reason, and explicit normalized
   origin-relative paths. No crawling or attack payloads are added.
2. Choose authentication and optional role identities; set the request budget.
3. Run, then inspect requests, coverage, and the [attack chain](#reading-the-attack-chain).

The target receives `GET` requests. OAuth token/form-login workflows also send authentication
`POST`s; API-key authentication may add a query parameter. Even GET can have side effects on
an unsafe endpoint. The default **20**, maximum **100** target-request budget is shared across
identities; untested paths remain marked **NOT TESTED**.

Manual browser sign-in requires Playwright Chromium on the runner. Finish closes the browser and
retains only target-origin cookies, with a 15-minute session lifetime. Exports in JSON, Markdown,
or HTML omit configured authentication values. Review response evidence for sensitive data before sharing.

| Authentication | What you provide |
| --- | --- |
| None / Bearer / Basic | No credential, token, or username/password |
| API key / custom headers / cookie | Named header/query key, header JSON, or cookie string |
| OAuth client credentials / refresh token / password | Explicit token endpoint and grant credentials; password grant only where permitted |
| Form login | Login endpoint, field names, username/password; not an arbitrary SSO automation flow |
| Mutual TLS | PEM client certificate/key and optional passphrase |
| Browser state | Exported cookie state; localStorage tokens are not replayed |
| Manual browser session | Complete SSO/MFA yourself, then Finish; no authentication bypass |

Use only authorized test identities. Private/loopback targets require explicit opt-in.
This observer is separate from the [AVIT ephemeral deployment/DAST flow](avit-integration.md).

### Reading the attack chain

Read left to right: **Scope & authority → Identity → Request → Response/control → Observation →
Impact hypothesis**. Solid edges are observed; dashed amber edges are unvalidated hypotheses.
Select a node for its chain; **Finding chains only** hides requests without findings. A `401/403`
records a denial for that request, not proof authorization holds everywhere.

## Triaging a scan report

**Triage a scan report** is false positive review for a scanner's report file. Every finding gets a
verdict (true positive, false positive, or ambiguous) with its evidence, in a findings report.

1. Open **Triage a scan report** and choose the report (**25 MB** maximum):
   - Invicti: XML, JSON, or the **Detailed Scan Report** PDF.
   - MobSF: report JSON or the **PDF Report**. A browser print of the MobSF web page is refused
     because its tables are paginated and would drop findings.
   - DefectDojo findings JSON, or SonarQube issues/hotspots JSON.

   The XML/JSON exports carry the most detail, such as lookup IDs and exact certainty, so prefer
   them when you have a choice.
2. Leave **Scanner** on auto-detect or select it. Optionally select the matching workspace
   and supply the destination finding reference.
3. Press **Triage findings** and inspect the saved findings/report. Every finding is retained and
   reviewed (no count limit; the model sees them in batches). Without a usable model, results are **NOT TRIAGED**, with
   conservative TRUE POSITIVE placeholders marked unverified, not model-verified vulnerabilities.
4. Review the evidence before selecting **Post to ServiceNow**, **Post to DefectDojo…**, or
   **Post to SonarQube…**. Posting requires confirmation and can change status.

Parsing is local; model triage sends finding evidence to your configured provider.
SARIF/Semgrep inputs belong in [Findings triage](#review-experience), not this importer.
Use the destination guide for write behavior: [AVIT](avit-integration.md),
[DefectDojo](integrations/defectdojo.md) (findings management), [SonarQube](integrations/sonarqube.md) (scanning tool).

## Ask Threatlint

Ask about the workspace, report, individual finding, or runtime scan—for example:
“Which control prevents this request from crossing tenant boundaries?”
Chat uses the selected provider and read-only repository tools, with up to 24 tool rounds per answer.
Context is delimited as untrusted evidence. Threads retain the last 20 turns within a
60,000-character history budget; failed/stopped answers are discarded.

## Metrics

Use [Metrics and dashboards](dashboards.md) to group saved findings and synced ServiceNow AVIT
or DefectDojo records by workspace, severity, specialist, or time. The separate all-AVIT summary
uses ServiceNow's Aggregate API to count every readable AVIT and apply filters server-side;
it does not download individual records. Choose a detailed source when tracker and local reports
may contain the same issue. Tracker refreshes are read-only and start only when you request one.
Scores describe reported evidence, not certified security posture.

## In-app help

Use control **?** tooltips or **Learn & videos** (`?` keyboard shortcut) for task guides, glossary,
and locally bundled videos. Rebuild videos with `npm --prefix web run videos`; requirements
are in `web/scripts/build-videos.cjs`.

## Developer flow

The sidebar groups **Test** (review, sources, runtime scanning, finding triage of AVITs/SCTASKs/ISSTs,
and triage/import), **Fix** (Findings and Ask Threatlint), **Track** (DefectDojo review, Metrics, and
Sidekick), and **Reference** (Agents, Skills, help). **Scan running app** is labelled *Preview · not yet
GA* while it matures. **Sidekick** is one nav item that opens a landing page of its capabilities
(vReports, loadouts, trends, ownership, and bulk actions) as cards; each capability page links back to
it. The Skills view shows the packaged workflow bodies and assignments from the
[registry](../src/threatlint/data/agent-skills.json).

## Desktop packaging

```bash
npm --prefix web run desktop:pack   # unpacked application, current platform
npm --prefix web run desktop:dist   # distribution targets, current platform
```

Targets: macOS DMG/ZIP, Windows NSIS, Linux AppImage/DEB; output: `web/release`.
Build on the target OS. Packages include the runner, UI, agents, skills, converter, and Python
source—not a Python interpreter or local models.

For an offline pack using the already installed Electron distribution, from `web/`:

```bash
npm run desktop:pack -- --mac --arm64 -c.mac.identity=null \
  -c.electronDist=node_modules/electron/dist -c.electronVersion=44.10.1
```

This command disables macOS signing. Do not equate packaging with signing, notarization, or
cross-platform runtime validation. Follow your organization's distribution policy.
The ZIP-reader override is explicit in the manifest/lockfile; revalidate after dependency changes.

## Tests and validation

See [Development](development.md) for prerequisites. These are commands to run, not a claim
that your checkout or live provider has passed:

```bash
npm --prefix web test
python -m pytest tests -q
npm --prefix web run test:browser
npm --prefix web run test:desktop
```

Browser tests need Playwright Chromium (`npx --prefix web playwright install chromium`), or
`THREATLINT_BROWSER_EXECUTABLE` pointing to installed Chromium/Chrome. Desktop tests accept
`THREATLINT_DESKTOP_EXECUTABLE` for a packaged app. Tests use deterministic fixtures; live
provider interoperability and model report quality need separate validation.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| No local models | Load a tool-capable model; start LM Studio; check URL/port and **Load models** |
| Model/API error or 429 | Check exact ID, credential source, account access, quota, and gateway URL |
| Word download missing | Check `THREATLINT_PYTHON` and that interpreter's `python-docx`; use Markdown meanwhile |
| Upload rejected / incomplete coverage | Check importer versus triage formats and limits; split by component/rule |
| Review disconnected | Keep completed reports; explicitly rerun the incomplete review |
| Inspection blocked | Use structured Read/Grep/Glob or one supported read-only Git command without shell syntax |
| Corrupt history | Back up original metadata; repair invalid JSON before restarting |
| Unsigned macOS warning | Follow device policy; sign/notarize before distributing |

## One codebase for browser and desktop

`web/desktop/main.cjs` calls `createWorkbench()` from `web/server.js` and loads the same
`web/public` UI. Changes to the shared server, libraries, or frontend affect both shells.
Use `desktop:dev` for live reload, `desktop:verify` / `desktop:sync` for build-stamp checks,
and optional `hooks:install` for the repository's Git hooks. See [Development](development.md).

## Code layout

| Area | Responsibility |
| --- | --- |
| `web/server.js`, `web/lib/http.cjs`, `web/lib/routes/` | Composition, loopback policy, HTTP endpoints |
| `web/lib/socket.cjs`, `pipeline.cjs`, `providers.cjs` | Review/chat actions, prompts, model streaming |
| `web/lib/store.cjs`, `report-writer.cjs`, `chat.cjs` | Persistence, reports, conversations |
| `web/lib/scm.cjs`, `runtime.cjs`, `metrics.cjs` | Source checkout, observations, dashboard facts |
| `web/public/` | Views communicating through `threatlint:*` DOM events |
