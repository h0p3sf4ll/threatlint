---
description: "Triage security scanner findings as true or false positives. Generates precise Semgrep rule tuning for FPs and confirms exploit paths for TPs. Accepts a SARIF file, Semgrep JSON output, or a threatlint report."
argument-hint: "Path to SARIF file, Semgrep JSON, threatlint report, or a ServiceNow AVIT number (e.g., /tmp/semgrep.json or AVIT000000095938462)"
---

Invoke the `appsec-fp-reviewer` agent to triage security scanner findings.

## Prerequisite: Semgrep Community Edition

Before any triage or rule validation, run `semgrep --version`. If it fails, stop and tell the user to install Semgrep Community Edition (`python3 -m pip install semgrep` or `brew install semgrep`), confirm with `semgrep --version`, and rerun this command. Do not continue without it.

## Routing

- If `$ARGUMENTS` contains ServiceNow AVIT numbers (`AVIT` followed by exactly 15 digits, e.g. `AVIT000000095938462`), run the **AVIT workflow** below instead of looking for a local findings file. The repository, branch, file, and rule come from the AVIT record itself; the current directory does not need to be the affected repository.
- If `$ARGUMENTS` is empty: look for a SARIF file, Semgrep JSON, or threatlint report in the current directory. Check these locations in order: `.sarif`, `semgrep.json`, `semgrep-results.json`, `results.sarif`, `*.sarif`, any `*.json` matching `semgrep` in the filename, or the most recent `*.md` threatlint report in the repo root.
- If `$ARGUMENTS` is a file path: use that file as the findings source.
- If `$ARGUMENTS` is a finding ID or range (e.g., `TM-001` or `TM-001..TM-005`): look for those findings in the most recent threatlint report in the repo root.
- If no findings file is found: tell the user to run Semgrep first (`semgrep --config=auto --json > semgrep.json`) or provide a path.

## AVIT workflow

This works on macOS, Linux, and Windows. Use a temporary working directory from the OS:
- macOS/Linux: `WORK=$(mktemp -d)`
- Windows PowerShell: `$WORK = Join-Path $env:TEMP "threatlint-$(Get-Random)"; New-Item -ItemType Directory $WORK`

Use `$WORK` for every path below. Never hard-code `/tmp`.

**Credentials.** Run `threatlint setup` once. It configures AWS SSO, ServiceNow, the Azure DevOps PAT, and the Semgrep token.
- The ServiceNow instance comes from `--snow-instance https://<instance>.service-now.com` or `THREATLINT_SNOW_INSTANCE`.
- The OAuth client and the Semgrep token (`/cfc-appsec-semgrep-scan/semgrep-token`) are read from AWS Parameter Store (us-west-2) with the user's AWS CLI profile (`--aws-profile`). If that fails, tell the user to run `threatlint aws login`, which signs in through a **private browser window** (avoiding Okta's "Conflicting User IDs specified on state token"), then retry.
- Azure DevOps access comes from `threatlint ado login` (a saved, validated PAT with Code: Read), `THREATLINT_ADO_PAT`, or `az login`. Check it with `threatlint ado status`.
- Never ask the user to paste a secret or PAT into the conversation. They run the login commands in their own terminal.

For each AVIT number:

1. **Fetch the AVIT and check its scope.**
   ```
   threatlint avit fetch <AVIT> -o $WORK/avit.md
   ```
   - Only AVITs in the AVR **CodeSecurity** view qualify. Membership is the view's rule, evaluated by ServiceNow.
   - The *Security Finding Source* (SAST, SCA, or Secrets) does not affect scope. It only decides how to triage and which Semgrep product to tune.
   - AVITs outside the view are listed as excluded: report them as out of scope and change nothing.
   - The file's *Review target* table lists the finding type, repository URL, branch, file, line, and rule taken from the AVIT fields.
2. **Check out exactly that repository and branch.**
   ```
   threatlint ado status
   threatlint avit checkout <AVIT> --dir $WORK/repo
   ```
   - For `SCM Tool = ADO` the repository is `https://dev.azure.com/{Organization Name}/{Project Name}/_git/{Repository}`, cloned on `{Project Branch}`. GitHub AVITs use `https://github.com/{Organization Name}/{Repository}` with `gh auth login` or `GH_TOKEN`.
   - If `threatlint ado status` shows no PAT and the clone fails, stop. Tell the user to run `threatlint ado login --organization <Organization Name>` in their terminal, then retry.
   - Do not triage against a different branch or a local copy.
3. **Triage against that checkout.** Give the agent `$WORK/avit.md` as the findings source and `$WORK/repo` as the repository. Start at the AVIT's File Path (and line/rule, when given) on that branch.
   - **SAST:** trace source to sink.
   - **SCA:** confirm the vulnerable package and version are actually resolved in the lockfile or manifest on that branch, and whether the vulnerable function or feature is reachable. For example, whether fast-xml-parser parses untrusted XML with `processEntities` enabled.
   - **Secrets:** decide whether the value is a real, usable credential, not a placeholder, test fixture, revoked key, or secret-store reference. **Never print the secret value.**
   - Write *Original finding* as `<AVIT>; <rule or vulnerability>; <scanner>; <path:line>`, one AVIT per finding.
4. **Save the report** as described under *Output*, using the AVIT checkout's repository name and branch in the filename. Keep the Markdown at `$WORK/fp_review.md`.
5. **Resolve the AVIT without asking.** Show the user the disposition, then run:
   ```
   threatlint avit resolve <AVIT> --report $WORK/fp_review.md --docx <saved .docx> --checkout $WORK/repo --yes
   ```
   For a SAST or Secrets false positive, the agent's report must contain a `**Tuned rule**:` YAML block, with the original rule plus the narrowest `pattern-not` or sanitizer, and optionally a `**Tuned rule fixtures**:` block. With a token, `curl -H "Authorization: Bearer $SEMGREP_APP_TOKEN" https://semgrep.dev/c/r/<rule-id>` returns the original Pro rule. Threatlint publishes and swaps the rule only when the original reproduces the finding and the tuned rule does not.
   - **TRUE POSITIVE:** only the Word report is attached, as `<AVIT>-threatlint-fp-review.docx`, with the work note "True positive, see attached report." The AVIT stays open.
   - **FALSE POSITIVE:**
     - The report is attached first.
     - The AVIT is closed (state 3 / substate 3) with the work note "Closed by Threatlint as a false positive, see attached report."
     - For SAST and Secrets, the rule is replaced in Semgrep by the validated tuned rule.
     - Matching open Semgrep findings are ignored as `false_positive`: Semgrep Code for SAST, Supply Chain for SCA, and Secrets for Secrets.
   - **AMBIGUOUS:** nothing changes.
6. **Clean up.** `threatlint avit resolve --checkout $WORK/repo` deletes the checkout itself once validation finishes. Then delete `$WORK`. Never leave a copy of the AVIT repository on the local drive, because it may contain live secrets.

Rule tuning runs once per rule. If a Semgrep policy already runs `<rule>.tuned`, later false positives of that rule are only triaged, not tuned again.

## Instructions for the Agent

Tell the agent:

1. Begin with the document header (repo name, date, input source, total finding count).
2. Parse the findings file. Print the total count before beginning analysis.
3. For each finding:
   a. Read the matched file at the flagged line with ≥60 lines of context (30 before, 30 after).
   b. Trace the input source: is the flagged value attacker-controlled?
   c. Trace to the sink: what transformations and validation occur along the path?
   d. Identify any code-level sanitizers that break the exploit path.
   e. Classify as TRUE POSITIVE, FALSE POSITIVE, or AMBIGUOUS with cited code evidence.
4. Apply the required finding-triage, Semgrep-tuning, evidence-analysis, and actionable-reporting skills. The current agent protocol supersedes the abbreviated instructions below.
5. For every FALSE POSITIVE:
   a. Generate a Semgrep rule patch using the lowest-level tuning option that correctly suppresses only this FP.
   b. State explicitly which true positives the patched rule still catches.
   c. Require the original rule for an exact patch. Label unexecuted validation NOT RUN and assess possible false negatives separately from the verdict.
6. For every TRUE POSITIVE: provide a concrete proposed code/configuration fix, implementation notes, owner/effort, regression assertions, and acceptance criteria. Proposals are NOT APPLIED.
7. For every AMBIGUOUS: keep open, state the exact blocking evidence, suggested owner, resolution plan, and interim action.
8. Produce the full three-tier professional report: executive summary and priority actions; detailed evidence-backed findings with original-ID mapping and proposed fixes; suppression impact, systemic causes, remediation roadmap, and acceptance matrix. Reconcile all input/duplicate/unreviewed counts. Never classify code as safe solely because it is admin-only, internal, test, generated, or vendored.
9. Do not modify any files.

## Output: Save as Word Document

After the agent delivers its report:

1. **Output directory**: the root of the current git repository (`git rev-parse --show-toplevel`), or current working directory if not in a git repo.

2. **Filename**: `<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx` (use today's date), where `<repo-name>` and `<branch>` are derived from:
   ```
   REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
   BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
   BRANCH=${BRANCH:-no-branch}
   ```

3. **Convert to Word document**:
   ```
   Write the full report text to a file in a temporary directory (`$WORK/fp_review.md`; see above)
   python3 ~/.claude/scripts/md_to_docx.py $WORK/fp_review.md <output-dir>/<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx
   (on Windows use `python` and `$HOME\.claude\scripts\md_to_docx.py`), then delete the temporary file
   Use a Python that has `python-docx` (check with `python3 -c "import docx"`). If the conversion fails, stop: do not run `avit resolve` until the Word report exists.
   ```

4. **Confirm** the saved path to the user.
