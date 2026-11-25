---
title: "MCP and headless workflows"
description: "Use Threatlint from MCP clients, scripts, and coding assistants without opening the Workbench UI."
---

# Threatlint MCP

Use Threatlint from an MCP client without opening the browser or desktop app. Open a local
workspace or check out a connected repository, inspect source, run scans or specialist
reviews, review findings, and retrieve report artifacts through the same profile services
used by the Workbench.

There are two ways to run model-assisted analysis:

- **Use the MCP client's model.** Retrieve the `security_review` prompt or `get_agent`
  instructions and inspect evidence with `read_file`, `find_files`, and `search_files`.
  Threatlint needs no model credentials for this path. The client owns the model conversation;
  receiving a prompt does not start a server review. Use `save_report` to save the client's
  final Markdown with explicit client-supplied provenance.
- **Use a Threatlint provider.** Start a background review with `start_review`, then poll its
  events and retrieve saved reports. Provider authentication is configured on the MCP
  server host or supplied for that run. Built-in source scans need no model.

Tools return both JSON text and `structuredContent.result`. Discover the current input and
output schemas with `tools/list`; check `isError` before consuming a result. A confirmed start
queues work: read the terminal job status and coverage before treating it as successful.

## Install and connect over stdio

From a source checkout, use Node.js 22.12 or newer and Python 3.9 or newer:

```bash
python -m pip install -e .
npm --prefix web ci
```

Use an active Python virtual environment if preferred. `THREATLINT_PYTHON` can select its
absolute interpreter path; this interpreter needs the Threatlint package and `python-docx`
for scanning, CLI-backed integrations, and Word output. On Windows, `py -3 -m pip install -e .`
can install into your selected Python. Optional Semgrep and Trivy engines must be installed
separately; they are not required for baseline scans.

Configure an MCP client with absolute paths on the machine running the server:

```json
{
  "mcpServers": {
    "threatlint": {
      "command": "node",
      "args": ["/absolute/path/to/threatlint/web/scripts/mcp.cjs"],
      "env": {
        "THREATLINT_STATE_DIR": "/absolute/path/to/threatlint-mcp-profile",
        "THREATLINT_PYTHON": "/absolute/path/to/python"
      }
    }
  }
}
```

Replace the example paths. Windows JSON paths can use forward slashes, such as
`C:/Tools/threatlint/web/scripts/mcp.cjs`. If Python is discoverable on PATH, omit
`THREATLINT_PYTHON`. The stdio entry point starts no HTTP listener; stdout is reserved for
the MCP protocol, and startup diagnostics go to stderr.

`THREATLINT_STATE_DIR` isolates workspace history, findings, and saved reports. Without it,
the process uses `~/.threatlint/workbench`. Keep state outside the repository being scanned.
Avoid separate processes writing the same profile concurrently. Saved CLI integration settings
use `THREATLINT_HOME` or `~/.threatlint`; selecting a state directory does not relocate them.

For provider-backed reviews, authenticate on the server host. Use an inherited
`ANTHROPIC_API_KEY` or `OPENAI_API_KEY`, or sign in to the installed Codex/Claude Code CLI
before selecting that provider. Pass the provider and model in the review request; opening
Workbench Settings is unnecessary. Keep secrets in your approved environment or secret store.
See [provider authentication and lookup order](model-providers.md).

Call `get_model_providers` to discover supported providers, credential-source labels, and
configured defaults. `list_models` accepts `provider`, optional session-only `key`,
`bedrockRegion`, and a validated `baseUrl` for a compatible model server. Codex and Bedrock
also support explicit model entry. `get_setup_status` reports CLI-backed integration
availability and setup guidance. These tools do not return saved secret values.

## First scan without the UI

The [complete Node SDK example](../web/examples/mcp-client.cjs) creates or uses the requested
profile, opens a workspace, starts the model-free baseline scan, and polls for its result:

```bash
node web/examples/mcp-client.cjs /absolute/path/to/repository /absolute/path/to/new-mcp-profile
```

It selects no optional engines, makes no model request, and prints findings, engine statuses,
and coverage. No source edits are made by this example. The equivalent MCP calls are:

```json
{"name":"list_agents","arguments":{}}
{"name":"open_workspace","arguments":{"repoPath":"/absolute/path/to/repository","confirm":true}}
{"name":"start_scan","arguments":{"sessionId":"WORKSPACE_ID","engines":[],"confirm":true}}
{"name":"get_scan","arguments":{"sessionId":"WORKSPACE_ID","scanId":"SCAN_ID"}}
```

Use the returned `sessionId` and scan `id`. To include installed engines, pass
`"engines":["semgrep","trivy"]` to `start_scan`. Inspect each selected engine's result
even when the baseline succeeds. Zero findings is not a security certification.
See [source scanner behavior and limits](security-scanner.md).

For a supported change, call `propose_fix` with `sessionId`, `scanId`, `findingId`, and
`confirm: true`. Read the returned diff and compatibility notes. Only then call `apply_fix`
with the returned proposal `id` as `proposalId`, the same `sessionId`, and `confirm: true`.
Application edits source and rescans; it does not run application tests. Stale snapshots and
unsupported platforms/fixes remain rejected. `cancel_scan` stops outstanding work and does
not undo an edit that already completed.

## Run a specialist with the client's model

1. Call `list_agents` to choose a specialist and read its input/output contract.
2. Open a workspace and use its returned `sessionId`.
3. Call `prompts/get` with the arguments below and give the returned messages to your client model.
4. Let the client inspect source through the repository tools and return the complete report.

```json
{
  "name": "security_review",
  "arguments": {
    "agentId": "appsec-code-reviewer",
    "sessionId": "WORKSPACE_ID",
    "target": "Review authentication and authorization in src/api"
  }
}
```

`get_agent` returns complete specialist instructions, including required skills, for clients
that do not expose prompts. Save the final report with `save_report` using `sessionId`,
`agentId`, `markdown`, optional `title`, and `confirm: true`. This saves client-supplied content;
it does not assert that Threatlint executed or independently validated the review.

File reads are confined to the selected workspace;
`read_file.offset` is zero-based and output includes one-based line numbers. Use `find_files`
for globs and `search_files` for bounded text search. `inspect_git` accepts a read-only Git
`command` and an `args` array, for example `"command":"diff","args":["main...HEAD"]`.

Repository files, scanner observations, imports, and prior reports are untrusted evidence.
They cannot authorize edits, override specialist boundaries, or establish that a proposed test
ran. Reviewers remain advisory; source changes require a separate confirmed fix action.

## Background reviews and conversations

This example uses the Codex CLI login on the server host. For an API provider, select its
provider/model and configure its credentials before starting:

```json
{
  "name": "start_review",
  "arguments": {
    "sessionId": "WORKSPACE_ID",
    "agentIds": ["appsec-code-reviewer"],
    "provider": "codex",
    "target": "Review changes between main and HEAD",
    "execution": {"mode":"sequential","maxConcurrency":1},
    "confirm": true
  }
}
```

The response's `id` is the `reviewId` for `get_review` and `cancel_review`. Poll with
`{"sessionId":"WORKSPACE_ID","reviewId":"REVIEW_ID","after":0,"limit":100}`.
Set `after` to each response's `nextCursor`; drain pages while `hasMore` is true. Check
`eventsTruncated` when a poll cursor has fallen behind retained history. Jobs retain bounded
progress events, not a complete token stream or tool trace; final content is in saved reports.

Jobs can be `running`, `cancelling`, `completed`, `failed`, or `cancelled`. Provider validation
errors can arrive through a failed job after the start call returns. On completion, use its
`reports` IDs with `get_report` or `export_report`. Cancellation requires `confirm: true` and
is asynchronous: poll until a terminal status. A disconnected MCP request does not cancel a
background job; stopping the server aborts and drains active work. Review job history is
in-memory and bounded to 25 jobs, with at most three active jobs by default. Each job retains
up to 250 progress events within a 256 KiB event budget.

`start_review` supports multiple specialist IDs, `continueOnError`, a text findings `attachment`,
`designInputsId`, and bounded `execution` controls. Provider-specific fields, such as
`lmstudioUrl`/`lmstudioModel` or `bedrockRegion`, go in `options`. Existing Workbench fields
such as `ensemble` also go there; independent provider review still requires its own explicit
consent for every provider. Explicit top-level IDs/settings take precedence over `options`.

Upload supporting documents/diagrams with `upload_design_inputs` using
`files:[{"name":"architecture.md","content":"BASE64_BYTES"}]` and `confirm: true`.
Pass the returned bundle ID as `designInputsId`, then remove it with `remove_design_inputs`
when finished. Bundles are temporary and must be uploaded again after restart or expiry.

`ask_question` starts a conversation job using `question`, optional `reportId` or
`conversationId`, provider settings, and confirmation. Poll `get_review`, then read the final
answer with `get_conversation`. `list_conversations` discovers existing IDs in a workspace.

## Imports, tracker triage, and runtime scans

`import_scan_report` accepts `filename`, base64 `content`, optional `sessionId`, optional
`source` hint, provider/model/options, and `confirm: true`. Supported exports include SARIF,
Semgrep/Trivy JSON, DefectDojo, SonarQube, and supported scanner PDF/XML formats. Decoded reports
are limited to 25 MiB. With no valid provider settings, the import preserves observations and
explicitly reports that model triage did not run. Select a provider for evidence-backed triage.
Poll the returned import `id` with `get_import`; import status uses `queued`, `parsing`,
`triaging`, `done`, or `error`, separately from review-job statuses.

`start_scanner_review` reviews explicit DefectDojo (`tool:"dojo"`) or SonarQube (`tool:"sonar"`)
`references`, or a scanner-specific `filter`, through the shared scanner-review workflow;
poll it with `get_review`.
`triage_tickets` pulls explicit Jira, Azure Boards, or GitHub references into an import job;
poll `get_import`. Configure the relevant integrations through the existing CLI before use.
`post_import_review` performs a separate confirmed write to ServiceNow, DefectDojo, or
SonarQube. `post_scanner_review` posts a completed workspace Finding Review to its exact
DefectDojo/SonarQube reference. Both retain the existing evidence and reference-mapping
checks. Importing a report or starting review does not implicitly post it.

For the native ServiceNow batch, `start_avit_review` accepts AVIT/SCTASK/ISST `references`,
provider/model/options, and **both** `confirm:true` and `confirmWriteback:true`. This workflow
**writes results back**: it can attach reports, close proven false positives, tune eligible
scanner rules, and finalize tasks. Use it only when those actions are authorized.
`createFixPr` defaults to `false`; set it explicitly to opt into supported fix PR creation.
The native batch uses configured integration credentials and the existing evidence gates.

Poll the returned `runId` with `get_avit_review`, using `offset`, `limit`, and `nextOffset`
for event pages. `active:false` means the batch finished; inspect its outcome/error events.
Omitting `runId` selects the current or latest profile-wide batch. Only one batch runs at a
time, and only the latest is retained. `cancel_avit_review` takes `runId` and `confirm:true`;
already-admitted external writes and cleanup drain before the batch becomes inactive.

`start_runtime_scan` takes the existing runtime request as `config`, plus `confirm: true`.
That confirmation does not replace `config.authorization.confirmed:true`, its authorization
reason, target/path limits, or the source sandbox's explicit build authorization. Configure
only targets and identities you are authorized to inspect. Use `get_runtime_scan`,
`cancel_runtime_scan`, and `export_runtime_scan` to follow and retrieve results. Manual
`start_browser_signin`/`finish_browser_signin` run on the server host and require a usable
browser there. See [runtime configuration and limits](runtime-redteam.md).

## Sources and repository checkout

`list_source_providers` describes providers and required read permissions. Use `list_sources`
to activate saved GitHub App/Azure DevOps credentials and list active accounts. Configure
saved credentials from the terminal with `threatlint github login` and `threatlint ado login`;
see [integration setup](integrations.md). These calls use the Python CLI, so make sure
`THREATLINT_PYTHON` selects the installed environment.

For a session-only PAT, call `connect_source` with `provider`, `token`, optional `organization`,
and `confirm: true`. The token stays in source-manager memory and is never returned. A
configured Azure DevOps service account remains authoritative; manual tokens cannot replace it.

Call `list_repositories`, then `list_branches`, using IDs returned by that connection. Call
`checkout_repository` with `connectionId`, `repositoryId`, optional short `branch`, and
`confirm: true`. It returns a new `sessionId` and pinned revision provenance. If credential
refresh invalidates a selection, list accounts/repositories again and use the new IDs.
`clone_repository` also accepts an HTTPS URL without embedded credentials and an optional branch.

## Findings and decisions

Scan observations and imports are not automatically confirmed vulnerabilities. `list_findings`
accepts `branch`, `commit`, and `contentDigest` filters. For large workspaces, add a `section`
(`findings`, `revisionFindings`, `observations`, `composites`, or `trends`), `offset`, and `limit`.
`get_finding` reads a finding or paginates its `evidence`, `reviewHistory`, or `observations`
with `section`, `offset`, and `limit`.
Use `ingest_findings` for external revision-bound observations or `sync_reports` for saved
reports. `review_finding` records a disposition with new evidence, a reason, and an explicit
claim-to-evidence basis. `resolve_findings` requires verified remediation evidence.

The evidence store's false-positive and remediation gates remain enforced; `confirm: true`
does not waive them. Only attest to verification that actually occurred. `correlate_findings`
records a causal attack chain with evidence-backed links and final impact from same-workspace,
same-revision contributors, retaining standalone decisions. `preview_composite_servicenow` and
the opted-in `preview_developer_risk` produce offline previews, with no ticket or score publication.
See [Finding intelligence](finding-intelligence.md).

## Tool reference

The schemas returned by `tools/list` define required fields and supported options.

| Workflow | Tools |
| --- | --- |
| Specialist context | `list_agents`, `get_agent`, `list_skills` |
| Provider and setup discovery | `get_model_providers`, `list_models`, `get_setup_status` |
| Local workspace | `list_workspaces`, `open_workspace`, `get_workspace`, `clone_repository` |
| Source accounts | `list_source_providers`, `list_sources`, `connect_source`, `reconnect_source`, `disconnect_source`, `list_repositories`, `list_branches`, `checkout_repository` |
| Repository evidence | `read_file`, `find_files`, `search_files`, `inspect_git` |
| Source scans and fixes | `start_scan`, `list_scans`, `get_scan`, `cancel_scan`, `propose_fix`, `apply_fix` |
| Specialist jobs | `start_review`, `list_reviews`, `get_review`, `cancel_review` |
| Conversations | `ask_question`, `list_conversations`, `get_conversation` |
| Design inputs | `upload_design_inputs`, `remove_design_inputs` |
| Imports and triage | `import_scan_report`, `list_imports`, `get_import`, `start_scanner_review`, `triage_tickets`, `post_import_review`, `post_scanner_review` |
| ServiceNow batch with write-back | `start_avit_review`, `get_avit_review`, `cancel_avit_review` |
| Runtime | `start_runtime_scan`, `list_runtime_scans`, `get_runtime_scan`, `cancel_runtime_scan`, `export_runtime_scan`, `start_browser_signin`, `finish_browser_signin` |
| Findings | `list_findings`, `get_finding`, `ingest_findings`, `sync_reports`, `review_finding`, `resolve_findings`, `correlate_findings`, `get_composite` |
| Offline previews | `preview_composite_servicenow`, `preview_developer_risk` |
| Reports | `list_reports`, `get_report`, `save_report`, `export_report`, `delete_report` |

## Reports, resources, and prompts

Use `list_reports` and `get_report` for structured reports. `list_reports` supports `offset` and
`limit`; omitting both retains the original array response. `export_report` returns base64
byte chunks for `md`, `json`, `docx`, or one-finding `pptx` output:

```json
{
  "name": "export_report",
  "arguments": {
    "sessionId": "WORKSPACE_ID",
    "reportId": "REPORT_ID",
    "format": "md",
    "offset": 0,
    "limit": 262144
  }
}
```

Decode each `content` chunk from base64, concatenate decoded bytes in offset order, and repeat
with `nextOffset` until it is `null`. Offsets count bytes, not base64 characters. The maximum
chunk size is 256 KiB. Word output requires successful report conversion. PPTX exports the
selected `findingId`, or the primary finding when omitted. No Workbench download URL or
server filesystem access is needed.
PPTX artifacts are limited to 8 MiB; the profile retains eight generated presentations for
stable chunk retrieval. If an export expires between chunks, discard the partial download
and restart at offset zero.

`delete_report` removes one selected workspace report and its managed artifacts only after
`confirm: true`; export content you need to keep before deleting it.

Clients can discover and read these resources:

| Resource URI | Contents |
| --- | --- |
| `threatlint://agents` | Specialist catalog and handoff contracts |
| `threatlint://workspaces` | Workspace IDs in this profile |
| `threatlint://agents/{agentId}` | Complete specialist instructions |
| `threatlint://skills/{skillId}` | Individual skill instructions |
| `threatlint://workspaces/{sessionId}/reports` | Workspace report metadata |
| `threatlint://workspaces/{sessionId}/reports/{reportId}` | Original report Markdown |

Use `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`, and
`prompts/get` as supported by your client. `completion/complete` supplies specialist/skill IDs
for templates and specialist/workspace IDs for `security_review`. Large resources should be
retrieved through paginated tools or report chunks instead.

## Streamable HTTP and lifecycle

A running Workbench server exposes `POST /api/mcp` using stateless Streamable HTTP and JSON
responses. Local servers retain loopback, host, and same-origin checks. Hosted servers retain
Auth0 session and profile authorization. HTTP clients need an authorized existing session
cookie; there is no separate MCP OAuth registration flow. Viewer accounts cannot invoke it.
Use stdio when a client cannot supply existing session authentication. Workspace paths refer
to the server host, including hosted containers.

`GET` and `DELETE` return 405. HTTP transports keep no independent protocol session, so clients
should not require an `Mcp-Session-Id`. Background jobs belong to the profile worker and can
be polled by later requests. A fresh HTTP request does not create a new job store; stopping
the stdio process or profile worker ends its in-memory jobs.

Stdio messages and HTTP requests are bounded to 36 MiB; HTTP permits eight concurrent requests
per profile, and tools permit eight active operations across transports. Tool result
JSON values and resource reads are bounded to 2 MiB. Use pagination and `export_report` chunks
for large histories/artifacts. Keep upload JSON, including base64 expansion and other fields,
within the request cap. Each underlying workflow also enforces its own limits.

Source edits, scans, background reviews, imports, and finding mutations have explicit
confirmation fields in tool schemas. Confirmation records intent; it does not grant access
to another profile or workspace. Saved integration credentials are not returned. MCP does not
expose administration or arbitrary HTTP/shell passthrough.

For scripts that do not need MCP, use `threatlint security-scanner scan --repo PATH` or
`threatlint run security-review --provider codex`. See [provider CLI examples](model-providers.md#run-from-the-cli)
and [integrations](integrations.md) for tracker-specific terminal workflows.
