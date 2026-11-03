# Integrations

Threatlint connects to the tools where findings live, so a reviewed verdict and its evidence end up
next to the finding instead of in a side channel. Integrations are grouped by **what the tool is**,
because that decides where a verdict belongs and what Threatlint may change.

| Type | What it is | Where the verdict goes | Built in |
| --- | --- | --- | --- |
| **Findings management** | A system of record that aggregates findings from many scanners and tracks their status. It does not scan code. | On the platform's finding: report attached, note, status. If the original scanner was Semgrep, Semgrep triage and rule tuning follow. | [DefectDojo](defectdojo.md) (`threatlint dojo`) |
| **Scanning tool** | A tool that analyzes code itself and owns the issues it raises. | Through the tool's own issue workflow: comment, then its false-positive / confirm transition. | [SonarQube / SonarCloud](sonarqube.md) (`threatlint sonar`) |
| **Secret validation** | A provider check that reports whether a detected credential is live. | Evidence for the FP reviewer (`VALID` / `INVALID` / `UNVERIFIED`), never the secret itself. | None. Validators come from plugins. |

The types are independent. Each has its own base class and package under
[`src/threatlint/integrations/`](../../src/threatlint/integrations/), and none imports another.
They share only plumbing: HTTPS-only URLs, token resolution, redirect-refusing requests, and verdict parsing.

## See what is installed

```bash
threatlint integrations list          # grouped by type, with the package that provided each
threatlint integrations list --json   # for scripts
```

## Every reviewable integration gets the same commands

Findings-management and scanning integrations both get these commands:

| Command | What it does | Changes the tool? |
| --- | --- | --- |
| `fetch [REF …] [filters] -o FILE` | Writes findings as an FP-review findings file | No |
| `checkout REF --dir DIR` | Clones the finding's repository and branch (and commit, when recorded) | No |
| `resolve REF --report MD …` | Writes the reviewer's verdict back | Yes, after confirmation |
| `note REF --message TEXT` | Adds a note only | Yes, after confirmation |
| `login [--url URL]` | Checks a token, then saves it to `~/.threatlint/` (mode 0600) | No |

How the types differ: `resolve` on a findings-management platform requires `--docx` (the report is
attached before any status change) and accepts the Semgrep options. On a scanning tool `--docx` is
optional and `--report-url` names where the full report lives.

## Secret validation and the FP reviewer

When a secrets finding is triaged, the FP reviewer uses validation evidence if a configured validator
produced it:

- **VALID**: the provider accepted the credential. The reviewer treats it as a live credential.
- **INVALID**: the provider rejected it. This supports, but does not alone prove, a false positive.
  The reviewer still checks code context and history.
- **UNVERIFIED** (no validator, disabled, network error, rate limit): this is not evidence either way.
  The reviewer decides from code context and labels validity unverified.

The reviewer never tests a credential itself and never prints secret values.

## Add your own

The community is welcome to add integrations. Ticketing systems, other findings platforms such as
ThreadFix, Faraday or ArmorCode, and other scanners such as Checkmarx, Snyk Code, Veracode or GitHub
code scanning all fit. Start with [Writing an integration](authoring.md).
