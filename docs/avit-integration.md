# AVIT triage integration: process and data flows

This document describes how Threatlint triages a ServiceNow AVR **Application Vulnerable Item (AVIT)**
from start to finish: setup, fetching, checkout, review, writing the result back to ServiceNow, and
Semgrep tuning. It covers every component, credential and data flow involved. The same flow runs from
`/fp-review AVIT000000000000000` in Claude Code and from the `threatlint avit …` commands. The
Workbench runs its own path, described at the end.

## Components

| Component | Role | Where it runs |
| --- | --- | --- |
| `threatlint` CLI (`src/threatlint`) | Setup, fetch, checkout, resolve, Semgrep tuning | User's machine (macOS, Windows, Linux) |
| `/fp-review` command + `appsec-fp-reviewer` agent | Orchestrates the flow and triages the finding (analysis only) | Claude Code |
| Threatlint Workbench (`web/`) | UI for triage, settings, closing false positives | Desktop app or local browser server (loopback only) |
| AWS IAM Identity Center + SSM Parameter Store (us-west-2) | Holds the ServiceNow OAuth client and the Semgrep token | AWS |
| ServiceNow AVR (`sn_vul_app_vulnerable_item`) | Source of AVITs; receives the report, work note and state change | `https://<instance>.service-now.com` |
| Azure DevOps / GitHub | Source code for the AVIT's repository and branch | `dev.azure.com`, `github.com` |
| Semgrep AppSec Platform | Finding triage and rule policies | `https://semgrep.dev` (same API as `semgrep.app`) |
| Semgrep CE + Pro engine | Local rule validation and tests | User's machine |

## One-time setup

```bash
threatlint setup          # interactive; each step is skipped when already configured
```

| Step | Command it runs | Stored where | Secret handling |
| --- | --- | --- | --- |
| AWS sign-in | `threatlint aws login` | `~/.aws/config` profile `appsec`; tokens in the AWS CLI cache | Opens a **private** browser window. The Identity Center region is detected from the portal URL. |
| ServiceNow | asks for the instance URL, then reads the OAuth client from Parameter Store, or prompts with hidden input | `~/.threatlint/servicenow.json` (owner-only) | Validated with a client-credentials token before it is saved |
| Azure DevOps | `threatlint ado login` | OS credential store (`keyring`), or `~/.threatlint/ado.json` (owner-only) | PAT (Code: Read) validated against the organization |
| Semgrep | `threatlint semgrep login` | OS credential store, or `~/.threatlint/semgrep.json` (owner-only) | Read from `/cfc-appsec-semgrep-scan/semgrep-token` or prompted with hidden input; validated against `/api/v1/deployments` |

On Windows, `~` is `%USERPROFILE%`. `THREATLINT_HOME` relocates `~/.threatlint`. The Workbench's
*Settings* page has a **ServiceNow** section and a **Semgrep** section that write the same files. They
show secrets masked and never send them back to the page.

**Behind a TLS-inspecting proxy:** the macOS keychains or the Windows certificate store are exported
to `~/.threatlint/ca-bundle.pem`. That bundle is passed to the AWS CLI (`AWS_CA_BUNDLE`), git
(`GIT_SSL_CAINFO`), Semgrep and Threatlint's own HTTPS calls. The Workbench trusts the OS store
directly.

## Process flow

```mermaid
flowchart TD
    A["/fp-review AVIT…"] --> B["threatlint avit fetch"]
    B --> C{"In the AVR CodeSecurity view?"}
    C -- no --> X["Report as out of scope. Change nothing."]
    C -- yes --> D["threatlint avit checkout: clone the AVIT's repo and branch"]
    D --> E["appsec-fp-reviewer triages the file, rule and line on that branch"]
    E --> F["Save the Word report"]
    F --> G["threatlint avit resolve"]
    G --> H{"Disposition"}
    H -- "TRUE POSITIVE" --> T["Attach Word report. Work note: 'True positive, see attached report.' AVIT stays open."]
    H -- AMBIGUOUS --> N["Nothing changes"]
    H -- "FALSE POSITIVE" --> P["Attach Word report. Close (state 3 / substate 3). Work note: 'Closed by Threatlint as a false positive, see attached report.'"]
    P --> S["Semgrep: ignore the matching open finding as false_positive"]
    S --> R{"SAST or Secrets?"}
    R -- no --> Z["Done (SCA: triage only)"]
    R -- yes --> Q{"A policy already runs rule.tuned?"}
    Q -- yes --> Z2["Done: triage only, no re-tuning"]
    Q -- no --> V["Validate the tuned rule locally"]
    V -- proven --> W["Publish org-private rule. Enable it in each policy in the original's mode. Disable the original."]
    V -- "not proven" --> Y["Leave the policy unchanged and report why"]
```

**Scope.** Every AVIT is reviewed, and its number may be `AVIT` plus 7 to 15 digits. Long numbers come from
the **CodeSecurity** view (code findings); shorter ones, such as `AVIT0042599`, come from other tools and views.
An AVIT is CodeSecurity when ServiceNow's rule for that form view (`sysrule_view`) selects it.
- **CodeSecurity:** the full flow: checkout, triage, closure or work note, and Semgrep.
- **Other tools:** validated from the AVIT's own evidence: scan details, affected asset or URL, proof, and the
  vulnerability definition. The code is read as well when a repository is named. Closure and work notes are
  the same; Semgrep is skipped.

Before this change, AVITs outside the CodeSecurity view were excluded. If the OAuth client can't read that rule, the view's SCM fields decide
instead. The *Security Finding Source* (SAST, SCA, Secrets) never decides scope. It only sets how the
agent triages and which Semgrep product is tuned.

**Repository target.** These come from the AVIT's form fields, resolved by label through
`sys_documentation`:
- SCM Tool, Organization Name, Project Name, Repository, Project Branch, File Path.
- ADO maps to `https://dev.azure.com/{Organization}/{Project}/_git/{Repository}`; GitHub maps to
  `https://github.com/{Organization}/{Repository}`.
- **Renamed repositories:** ServiceNow keeps the repository name from scan time. If an ADO clone
  fails with *not found*, Threatlint reads the repository's GUID from the Semgrep project
  (`{Project}/{Repository}`), asks Azure DevOps for that GUID's current name, and clones that instead.
  For example, `pepgpt-workflow-api` was renamed to `pepgpt-pro-api`. Semgrep matching keeps using
  the original project name, which is what Semgrep still calls it.
- The clone is shallow and single-branch. Credentials go to git through `GIT_CONFIG_*` environment
  variables, never on the command line or in `.git/config`.

**Triage rules.**
- **SAST:** trace source to sink.
- **SCA:** check whether the vulnerable version is actually resolved, and whether the vulnerable feature
  is reachable.
- **Secrets:** decide whether the value is a real credential. The value is never written to the report;
  it is referred to by path, line, key name and characterization only.

**Write-back.**
- The Word report is the **only** attachment, named `<AVIT>-threatlint-fp-review.docx`. It is uploaded
  **before** any state change, and is skipped if a file of that name is already attached.
- False positives are closed automatically, without a prompt. True positives and ambiguous findings
  never change state.
- The resolver reports the state ServiceNow actually stored. Business rules can override the
  substate.

**Semgrep tuning.** This runs only for a SAST or Secrets false positive, and needs both the reviewer's
`**Tuned rule**:` block and the AVIT checkout.
- **Once per rule:** if any policy of the product already runs an enabled `<rule-name>.tuned`, Threatlint
  stops here. That covers a similar false positive that was already tuned.
- **Otherwise:** the public API cannot edit a rule in place, so Threatlint replaces the rule:
1. Validate the tuned rule with `semgrep --validate` and run its fixtures with `semgrep --test`. Using
   the Pro engine when installed, require that the **original rule reproduces the finding** and the
   tuned rule does not. Otherwise stop (fail closed).
2. Publish the rule with `semgrep publish --visibility=org_private`.
3. For every policy of the matching product that runs the original rule: set the tuned rule to the
   original's mode, then set the original to `MODE_DISABLED`
   (`PUT /api/policies/v1/deployments/{id}/{policy}/rules/{path}`).
4. Print the rollback: re-enable the original and disable the tuned rule.

The finding triage (step S) always happens before rule tuning. If tuning is not proven, the false
positive stays ignored for its fingerprint on later scans and branches.

## Data flows

```mermaid
sequenceDiagram
    participant U as User / Claude Code
    participant T as threatlint CLI
    participant A as AWS (SSO + SSM)
    participant S as ServiceNow AVR
    participant G as Azure DevOps / GitHub
    participant M as Semgrep (semgrep.dev)
    U->>T: /fp-review AVIT…
    T->>A: SSM GetParameters (ServiceNow client, Semgrep token)
    T->>S: OAuth client_credentials → token
    T->>S: GET sn_vul_app_vulnerable_item, sysrule_view, sys_documentation
    T->>G: git clone --branch <Project Branch> (PAT / Entra token in env)
    U->>U: appsec-fp-reviewer reads the checkout (local only)
    T->>S: POST attachment/file (.docx), then PATCH state/substate/work_notes
    T->>M: GET findings / secrets → POST triage (ignored, false_positive)
    T->>M: semgrep publish (tuned rule) → PUT policy rule modes
```

| Data | From → to | Protection |
| --- | --- | --- |
| ServiceNow OAuth client | Parameter Store or saved config → Threatlint → `oauth_token.do` | Sent only to `*.service-now.com` / `*.servicenowservices.com` (or `THREATLINT_SNOW_ALLOWED_HOSTS`); redirects refused |
| AVIT fields | ServiceNow → `avit.md` → agent | Treated as untrusted evidence, never as instructions |
| Source code | ADO/GitHub → temporary checkout → agent | Read-only analysis. `avit resolve --checkout` deletes the checkout once validation finishes, even on error (`--keep-checkout` keeps it). |
| ADO PAT / GitHub token | Credential store → git environment | Never in argv, `.git/config`, logs or reports |
| Report | Agent → Word document (temporary folder) → ServiceNow attachment | Secret values redacted; no credential in the report; never saved elsewhere locally, and deleted after upload |
| Semgrep token | Credential store / Parameter Store → `semgrep.dev` | Fixed HTTPS host; redirects refused |
| Model traffic (Workbench) | Prompts and inspected source → selected provider | Requires explicit consent; keys from the session, environment, `~/.claude/settings.json`, Codex API key or `gh auth token` |

## Workbench: False positive review

**Test → False positive review** in the sidebar takes one AVIT or a list of up to 50, separated by
commas, spaces or new lines. AVITs run **one at a time**, and each gets its own result card:

1. **Fetch** (`threatlint avit fetch`). AVITs outside the CodeSecurity view are marked *Out of scope*.
2. **Clone** (`threatlint avit checkout`) the AVIT's repository and branch.
3. **Triage** with the Findings triage agent and the model chosen in *Settings*.
4. **Write** the AVIT's own Markdown and Word report in a temporary folder. Credential-like values from
   the flagged file and its directory are replaced with `[REDACTED]` first, in case the model printed one.
5. **Resolve** (`threatlint avit resolve --checkout`). This attaches that AVIT's Word report,
   closes it as a false positive or leaves it open with the true-positive note, then ignores and
   tunes in Semgrep. It also deletes the checkout.

Each card shows the stage, disposition, and ServiceNow and Semgrep outcome. **Reports are not kept
locally:** once a report is attached to its AVIT, its files and history entry are deleted, so
ServiceNow holds the only copy. One
AVIT failing does not stop the rest. *Stop* cancels before the next AVIT starts. A ServiceNow update
that has already started always finishes, so an AVIT is never left half-updated.

ServiceNow, Git and Semgrep steps go through the same Python CLI as `/fp-review`, so behaviour is
identical. The desktop app bundles the CLI under `Resources/python`. It uses the first Python on
`PATH` that has `python-docx` and `keyring` (override with `THREATLINT_PYTHON`).

## Workbench: report reader

The Workbench runs the same triage with the configured model.
- **Settings:** *Settings → ServiceNow / Semgrep* holds the shared configuration.
- **Close action:** *Close FP & tune Semgrep…* on a FALSE POSITIVE finding calls
  `/api/servicenow/close-false-positive`, with the same attachment, state values and work note as the
  CLI.
- **Semgrep:** `/api/semgrep/false-positive/{matches,ignore}` re-match the narrow rule/project/file
  scope on the server before ignoring anything.

## Re-running the Semgrep step

If the Semgrep step didn't run, or ran against the wrong project, after an AVIT was closed:

```bash
threatlint avit semgrep <AVIT> [--line N]
```

- It acts only when ServiceNow shows the AVIT **Closed** with the Threatlint false-positive work note.
- It matches the AVIT's project, file, rule and line (±3), then ignores those findings as
  `false_positive`. Use `--line` when the AVIT doesn't record one.
- Semgrep applies the triage to every finding with the same fingerprint, i.e. the same line on every
  branch.
- Without a line, every open finding of that rule in the file is ignored. Pass `--line` so that
  unrelated lines in the same file stay open.

## Known limits

- **Substate:** ServiceNow may not store substate 3 for Closed, if a business rule or the choice list
  disallows it. The resolver reports the stored value.
- **Pro and interfile rules:** these may not reproduce locally. Tuning then fails closed and the
  finding is only triaged.
- **Deployment:** PepsiCo has one Semgrep deployment, ID **26306** (`https://semgrep.dev/api/agent/deployments/26306`).
  Threatlint selects it by ID; `THREATLINT_SEMGREP_DEPLOYMENT` or `--semgrep-deployment` override it.
  Semgrep's v1 findings and triage endpoints only accept the deployment's slug in the path
  (`pepsico_poc`, which they look up from the ID). The policies and secrets endpoints take the ID.
- **Project names:** Semgrep names ADO projects `{Project Name}/{Repository}` (e.g.
  `Development_Solutions/Canvas-dev2.bijay.shrestha`), and GitHub projects `{owner}/{repo}`. Findings
  are matched on that name, the AVIT's file, ±3 lines, and the rule.
- **Network:** `semgrep.app` may not resolve on corporate DNS. `THREATLINT_SEMGREP_API` defaults to
  `https://semgrep.dev`.
