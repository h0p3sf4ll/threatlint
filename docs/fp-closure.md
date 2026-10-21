# Closing false positives across trackers

Threatlint's Findings triage agent (`appsec-fp-reviewer`) reviews scanner findings against the source
code and gives each one a disposition: **TRUE POSITIVE**, **FALSE POSITIVE**, or **AMBIGUOUS**. When
it confirms a false positive, the Workbench can close the tracked item for you, with the evidence
attached, in any of three systems:

| Tracker | Item | What "close" does |
| --- | --- | --- |
| ServiceNow AVR | Application vulnerable item (`AVIT0012345`) | Attaches the report, adds a work note, sets *Closed / False Positive* |
| Azure DevOps Boards | Work item (`ADO-4821`) | Attaches the report, adds a discussion comment, moves the item to its *Closed* state |
| GitHub Advanced Security | Code-scanning alert (`GHAS-owner/repo#12`) | Files the report in a closed tracking issue, dismisses the alert as *false positive* with a comment linking it |

In every tracker the note starts with **"Closed by Threatlint as a false positive."** and names the
finding, its confidence, the reviewing agent, and the attached report. The report file is
**prefixed with the item's ID**, for example `AVIT0012345-threatlint-fp-review.md`,
`ADO-4821-threatlint-fp-review.md`, or `GHAS-acme-web-12-threatlint-fp-review.md`. A `.docx` copy is
attached as well when Word export is available.

After closing, the same dialog can **tune Semgrep** so the false positive does not come back. See
[Semgrep tuning](#semgrep-tuning) below.

## CodeSecurity only

Semgrep reports code findings only, so Threatlint triages and closes only code-security items:

- **ServiceNow AVR:** an AVIT qualifies only when its source, scanner, category, or type field (or
  its vulnerability entry) matches `code security`, `SAST`, `static application`, `static code`, or
  `Semgrep`. AVITs from other AVR views (DAST, container, infrastructure, and so on) are skipped and
  listed as *Excluded*. Closing one is refused before anything is attached or changed. To match a
  different label, set `THREATLINT_SNOW_CODE_SECURITY_PATTERN` to a regular expression.
- **Azure DevOps:** the work item's tags, title, or area path must match the same terms (plus
  `code scanning`). Otherwise it is refused unchanged. To match a different label, set
  `THREATLINT_ADO_CODE_SECURITY_PATTERN`.
- **GitHub Advanced Security:** code-scanning alerts are code findings by definition. Dependabot
  and secret-scanning alerts are not used.

## How the agent names tracker items

The FP reviewer writes each finding's *Original finding* line as
`<tracker ID>; <rule ID>; <scanner/version>; <path:line>`. For example:

```text
**Original finding**: AVIT0012345; javascript.express.security.audit.xss.direct-response-write; Semgrep 1.107; src/routes/view.js:42
**Original finding**: ADO-4821; python.flask.security.injection.raw-html-concat.raw-html-format; Semgrep 1.107; app/views.py:12
**Original finding**: GHAS-acme/web#12; js/sql-injection; CodeQL 2.19; src/db.js:30
```

Each finding must reference exactly one tracker item. A finding that names several is refused, so
nothing gets closed by accident. The dialog pre-fills the Semgrep rule, file, and line from this
line.

## Using it in the Workbench

1. **Get findings into a triage report.** For ServiceNow, list the AVITs in the run. For Azure
   DevOps or GitHub, attach the export or SARIF file, or name the items in the review scope.
2. **Configure credentials** in *Model & settings*. They stay in memory for the session only and are
   never written to disk.
   - **ServiceNow:** click **Sign in with AWS SSO**. Sign-in opens in a private browser window and
     loads the OAuth client from Parameter Store. A normal window would share your Okta session and
     fail with *Conflicting User IDs specified on state token*. The OAuth client needs write access
     to `sn_vul_app_vulnerable_item` and `sys_attachment`.
   - **Azure DevOps:** enter the organization slug, the project, and a PAT with
     *Work Items: Read & write*.
   - **GitHub:** enter a token with *Code scanning alerts: write* (`security_events`) and
     *Issues: write* on the repository.
3. **Open the report.** Every FALSE POSITIVE finding has a **Close FP & tune Semgrep…** button. The
   dialog shows which tracker item the finding references. Each step runs only after you confirm it.

## What happens, in order

The server checks that the report is a Findings triage report and that the finding is marked
`FALSE POSITIVE`. It also checks that the finding references exactly one item, and that the item is
a CodeSecurity finding. Then:

1. **Attach first.** The report is uploaded before any state change, so an item is never closed
   without its evidence.
   - **ServiceNow:** `POST /api/now/attachment/file`.
   - **Azure DevOps:** `POST _apis/wit/attachments`, then an `AttachedFile` relation.
   - **GitHub:** code-scanning alerts cannot hold files, so the report goes into a tracking issue in
     the same repository. The issue is then closed.
2. **Close with the note.**
   - **ServiceNow:** state and substate are set to the instance's own *Closed* and *False Positive*
     choice values, read from `sys_choice`. Override them with `THREATLINT_SNOW_FP_STATE` and
     `THREATLINT_SNOW_FP_SUBSTATE`.
   - **Azure DevOps:** the item moves to the *Closed* state of its work item type, or the first
     *Completed* state if there is no *Closed*. Override it with `THREATLINT_ADO_CLOSED_STATE`.
   - **GitHub:** the alert is dismissed with `dismissed_reason: "false positive"`.
3. **Report what was stored.** The dialog shows the state the tracker actually saved. If a business
   rule, approval, or workflow kept the item open, you see that instead of a false success.

Every request refuses redirects, so a token can only go to the validated API host. ServiceNow
instances must be `*.service-now.com` or `*.servicenowservices.com`, or listed in
`THREATLINT_SNOW_ALLOWED_HOSTS`.

## Semgrep tuning

The Semgrep API token is loaded during AWS SSO sign-in, from
`/cfc-appsec-semgrep-scan/semgrep-token`. `SEMGREP_APP_TOKEN` overrides it.

1. **Find matches** lists open findings for exactly that rule, project, and file, within 3 lines.
2. The findings you confirm are triaged as *ignored / false_positive*, with a note that references
   the report and tracker item.
3. Semgrep keeps that triage for the same fingerprint on later scans and other branches.

Before ignoring anything, the server runs the match again and ignores only findings that are still
inside it. Semgrep's public API cannot edit rule logic, so a rule change such as a `pattern-not` or
path exclusion stays a proposal in the report for the scanner owner.

## Measuring efficacy

`web/eval/run-avit-eval.cjs` runs the real FP reviewer on CodeSecurity AVITs, scores its verdicts
against ground truth, and exercises the closing step.

- **Fixture mode** (the default) builds the AVITs from real Semgrep registry results on
  `web/eval/fixture-repo`. The ground truth was set by reading the code.
- **Live mode** reads real AVITs from ServiceNow. Set all of these:
  - `THREATLINT_SNOW_INSTANCE`, `THREATLINT_SNOW_CLIENT_ID`, `THREATLINT_SNOW_CLIENT_SECRET`
  - `THREATLINT_EVAL_AVITS`: the AVIT numbers
  - `THREATLINT_EVAL_REPO`: the checked-out repository
  - `THREATLINT_EVAL_TRUTH`: a JSON file mapping each AVIT to `"TRUE POSITIVE"` or `"FALSE POSITIVE"`

In both modes, closing is exercised only against recording stand-ins, so no real tracker is changed.
Results go to `web/eval/results/`, and `build_fp_deck.py` turns them into
`docs/threatlint-fp-closure.pptx`.

```bash
cd web && ANTHROPIC_API_KEY=... node eval/run-avit-eval.cjs --model claude-opus-5-5
cd .. && python3 build_fp_deck.py
```

**The metric that matters most is unsafe closures:** real vulnerabilities marked FALSE POSITIVE. Every
closure is gated on a human confirming each step, and a verdict never closes anything on its own.
