---
description: "Triage scanner findings or review ServiceNow AVIT and ISST records with the shared Threatlint headless workflow."
argument-hint: "SARIF/Semgrep report path, AVIT number, ISST number, or SCTASK number"
model: claude-opus-5-5
---

Use the `appsec-fp-reviewer` agent for findings-file reviews. For ServiceNow
records, delegate orchestration to the Threatlint CLI so Claude Code, Codex,
and Copilot use the same checkout, report, verdict, attachment, closure, and
Semgrep rule-tuning workflow. Do not use a browser or UI for record actions.

## Route the request

- **ISST** (`ISST` followed by digits): run
  `threatlint run fp-review --provider claude-code --isst <ISST> --resolve-avits --yes`.
  The CLI reads the ISST repository and branch, discovers associated AVITs,
  reviews each finding, attaches reports to AVITs, and posts the true-positive
  reports and summary to the ISST. Repeat `--isst` for multiple records.
- **AVIT** (`AVIT` followed by 7 to 15 digits): run
  `threatlint run fp-review --provider claude-code --avit <AVIT> --resolve-avits --yes`.
  Repeat `--avit` for multiple records. The CLI checks out each AVIT's recorded
  repository and branch and applies its verdict with no further prompt.
- **SCTASK** (`SCTASK` followed by digits): list its AVITs with
  `threatlint sctask avits <SCTASK>`, run the shared `--avit` command for every
  listed AVIT, then run `threatlint sctask close <SCTASK> --yes` if every
  review completed. The task command copies the latest AVIT reports and adds
  the outcome comment. Report any partial completion explicitly.
- **Report-only AVIT review**: omit `--resolve-avits --yes` when the user asks
  only for analysis. Do not infer write-back authorization from a findings-file
  review.
- **SARIF, Semgrep JSON, or Threatlint report**: pass the file to the
  `appsec-fp-reviewer` agent. If no path was supplied, look for `.sarif`,
  `semgrep.json`, `semgrep-results.json`, `results.sarif`, or the latest
  Threatlint Markdown report in the repository. If none exists, ask for the
  findings source.

## Tracker workflow outcomes

The shared CLI keeps its source checkout and report files in a temporary
directory and removes them after the run. It writes a Word report to each
reviewed AVIT. A true positive retains an open AVIT with the report attached.
A false positive attaches the report, closes the AVIT, triages the matching
Semgrep finding, and tunes eligible SAST or Secrets rules. SCA false positives
receive Supply Chain triage; they have no code rule to tune. A finding without proof of FP beyond reasonable doubt is TRUE POSITIVE with a conservative
decision basis and stays open; it is not labeled a confirmed exploit. ServiceNow and Semgrep are separate
writes, so check each record's printed result and report any partial failure.

Use `threatlint setup --check` when credentials or prerequisites are missing.
Never ask the user to paste credentials into the conversation. Tell them the
specific login command reported by the setup check. Do not reimplement the
AVIT or ISST workflow with manual ServiceNow or Semgrep calls.

## Findings-file report

Give the selected file to `appsec-fp-reviewer` and require its full
**Finding Review**: original ID mapping, code citations, disposition and
confidence for each finding, proposed fixes, Semgrep tuning proposals with
false-negative analysis, regression assertions, and a remediation roadmap.
The agent must keep the workspace read-only and label unrun validation
**NOT RUN**. For a false positive, require the original Semgrep rule before
claiming an exact tuned patch; never invent a rule or a passing test result.

Save a findings-file report as a Word document in the repository root, or the
current directory when there is no repository. Use the filename
`<repo-name>-<branch>-fp-review-YYYY-MM-DD.docx` and the bundled
`md_to_docx.py` converter. Confirm the saved path. This local output rule does
not apply to tracker reviews, whose reports are stored as AVIT attachments.


The `threatlint run fp-review --findings <file>` runner performs local tuning validation
automatically for eligible FPs and appends its execution results. For direct-agent reviews or
to retry an existing report after completing rule evidence, run
`threatlint semgrep tune-report --report <markdown> --repo <checkout> --output-dir <bundle>`
after generating the report. It validates the supplied complete tuned rule and TP/FP fixtures
with Pro, and saves local rule files plus an execution manifest. It does not publish to Semgrep
or upload scan results. Report every BLOCKED tuning and do not call the workflow complete if
an eligible FP still lacks validated tuning. Use the existing native Semgrep login; never ask
for its token in chat. Preserve the actual input scan's engine in provenance.
