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

Credentials: the ServiceNow instance comes from `--snow-instance https://<instance>.service-now.com` or `THREATLINT_SNOW_INSTANCE`. The OAuth client and the Semgrep token (`/cfc-appsec-semgrep-scan/semgrep-token`) are read from AWS Parameter Store (us-west-2) with the user's AWS CLI profile (`--aws-profile`). If access fails, tell the user to run `threatlint aws login`, which signs in through a **private browser window** to avoid the Okta "Conflicting User IDs specified on state token" error, and retry. Never ask the user to paste a secret into the conversation.

For each AVIT number:

1. **Fetch the AVIT and check its scope.**
   ```
   TIMESTAMP=$(date +%s)
   threatlint avit fetch <AVIT> -o /tmp/avit_${TIMESTAMP}.md
   ```
   The file's *Review target* table lists the finding type, repository URL, branch, file, line, and rule taken from the AVIT fields (SCM Tool, Organization Name, Project Name, Repository, Project Branch, File Path, Security Finding Source).
   - Only **CodeSecurity** and **Secret** AVITs qualify. AVITs from other AVR views are listed as excluded: report them as out of scope and change nothing.
2. **Check out exactly that repository and branch.**
   ```
   threatlint avit checkout <AVIT> --dir /tmp/avit_${TIMESTAMP}_repo
   ```
   - For `SCM Tool = ADO` the repository is `https://dev.azure.com/{Organization Name}/{Project Name}/_git/{Repository}`, cloned on `{Project Branch}`. GitHub AVITs use `https://github.com/{Organization Name}/{Repository}`.
   - Authentication comes from `THREATLINT_ADO_PAT` (Code: Read), `az login`, or the user's git credential helper for ADO, and from `gh auth login` / `GH_TOKEN` for GitHub.
   - If the clone fails, stop and report the access hint. Do not triage against a different branch or a local copy.
3. **Triage against that checkout.** Give the agent the AVIT file as the findings source and the checkout as the repository.
   - Start at the AVIT's File Path (and line/rule, when given), reading the file on that branch.
   - For a Secret finding, decide whether the flagged value is a real, usable credential, not a placeholder, test fixture, example, revoked or rotated key, or reference to a secret store. Check git history on that branch for the value, but **never print the secret value**; redact it in the report.
   - Write *Original finding* as `<AVIT>; <rule>; <scanner>; <path:line>`, one AVIT per finding.
4. **Save the report** as described under *Output*. Use the AVIT checkout's repository name and branch in the filename and save it in the current repository root. Also keep the Markdown at `/tmp/fp_review_${TIMESTAMP}.md` for step 5.
5. **Resolve the AVIT.** Show the user the disposition and ask for confirmation, then run:
   ```
   threatlint avit resolve <AVIT> --report /tmp/fp_review_${TIMESTAMP}.md --docx <saved .docx> --yes
   ```
   - **TRUE POSITIVE:** the report is attached to the AVIT as `<AVIT>-threatlint-fp-review.md` (and `.docx`), with a work note. The AVIT stays open for remediation.
   - **FALSE POSITIVE:**
     - The report is attached first.
     - The AVIT is set to Closed / False Positive with the comment "Closed as false positive by Threatlint fp-review agent".
     - Matching open Semgrep findings (same project and file, within ±3 lines, and the same rule for CodeSecurity) are ignored as `false_positive`. CodeSecurity AVITs are ignored in Semgrep Code and Secret AVITs in Semgrep Secrets.
     - Rule-logic changes remain proposals in the report.
   - **AMBIGUOUS:** nothing changes.
6. **Clean up.** Delete `/tmp/avit_${TIMESTAMP}.md`, `/tmp/fp_review_${TIMESTAMP}.md`, and the checkout directory.

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
   TIMESTAMP=$(date +%s)
   Write the full report text to /tmp/fp_review_${TIMESTAMP}.md
   python3 ~/.claude/scripts/md_to_docx.py /tmp/fp_review_${TIMESTAMP}.md <output-dir>/<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx
   rm /tmp/fp_review_${TIMESTAMP}.md
   ```

4. **Confirm** the saved path to the user.
