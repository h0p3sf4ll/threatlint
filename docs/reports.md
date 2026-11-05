# Turn a finding into an engineering handoff

A useful security report answers three questions: **what matters, where is the
evidence, and what should we do next?** A file attachment is only the delivery format.

## What to expect

- **Decision first:** risk, scope, priorities, and unresolved uncertainty.
- **Evidence next:** the original finding ID, inspected file/line, attacker path,
  and relevant controls.
- **Action last:** a proposed fix, compatibility notes, suggested owner/effort,
  regression assertions, and acceptance criteria.

Finding reviews use the title **Finding Review** and exactly two dispositions: TRUE POSITIVE
or FALSE POSITIVE. FP requires evidence disproving the scanner claim beyond reasonable doubt.
If that proof is missing, the finding remains open as a conservative TP with its actual
confidence, evidence gaps and validation limits. A conservative TP is not a confirmed exploit.
The `fp-review` command and filename suffix remain compatible with existing integrations.

Eligible Semgrep false positives retain rule tuning. The tracker workflow validates complete
rules and TP/FP fixtures before publication; missing or failed tuning is reported as incomplete.
The findings-file CLI runner automatically validates eligible FP tuning before saving the
report and records blocked tuning as an incomplete run. To validate an existing local/no-cloud
report independently, include the full rule and fixtures in the review and run:

```bash
threatlint semgrep tune-report --report review.md --repo /path/to/checkout --output-dir /path/to/tuned-rules
```

This uses Pro to validate the exact FP location and retained TP fixtures, saves one cumulative
replacement per original rule, and records a per-finding `tuning-manifest.json`. It never uploads
findings or publishes rules. Only validated replacements are saved; blocked proposals return
an unsuccessful exit status. Use the manifest to replace the listed original IDs in the local
scan configuration. Adding both the original and replacement would keep the original noise.

Semgrep token precedence is environment, native Semgrep settings, Threatlint saved login, then
Parameter Store. The native login defaults to `~/.semgrep/settings.yml` and respects
`SEMGREP_SETTINGS_FILE`. A token alone is not proof that Pro is installed: Threatlint checks the
matching engine and does not silently downgrade. Reports preserve the input scan's actual
engine provenance instead of inferring it from the installed CLI version.

**A proposed test is not a passed test.** Look for actual execution evidence;
otherwise validation remains **NOT RUN**. A report, clean guard run, or dashboard
is not proof that an application is secure.

## Where the report goes

| Workflow | Output |
| --- | --- |
| `threatlint run MODE` | Word when conversion succeeds; Markdown fallback otherwise |
| Claude Code slash commands | The command coordinates export after the analysis |
| Native agent/chat invocation | Client-dependent; a response in chat is not a saved file |
| Workbench | Review results and the export controls described in the [guide](workbench.md) |
| Workbench → Triage a scan report | A findings report (Markdown and Word) saved in Findings from an Invicti, MobSF, DefectDojo, or SonarQube export; see [the guide](workbench.md) |
| CI snapshot runner | The configured Markdown report/artifacts; see [CI templates](ci-templates.md) |
| Teams | A conversation response, split into messages when needed |

For the direct CLI, `--output-dir DIR` chooses the destination; otherwise it uses
the repository root. Its basename is:

```text
<repo>-<branch>-<mode>-local-YYYY-MM-DD
```

The `-local-` suffix is the CLI's current naming convention, even when the chosen
model provider is cloud-hosted. It is not a data-residency guarantee.

Native command filenames are command-specific. Examples:

| Command | Typical basename |
| --- | --- |
| `/threat-model` | `<repo>-<branch>-threat-model-YYYY-MM-DD` |
| `/threat-model src/auth` | `<repo>-<branch>-threat-model-src-auth-YYYY-MM-DD` |
| `/security-review` | `<repo>-<branch>-security-review-YYYY-MM-DD` |
| `/security-review 42` | `<repo>-<branch>-security-review-pr42-YYYY-MM-DD` |
| `/fp-review` | `<repo>-<branch>-fp-review-YYYY-MM-DD` |

Repository names are lowercased, spaces become hyphens, and branch slashes become
hyphens. Threat-model commands may choose a supplied path's directory; review
commands generally use the repository root. The command confirms the actual path.
For exact conventions, consult the relevant [command definition](../src/threatlint/data/commands/).

## Convert an existing report

Install Threatlint and its complete script bundle:

```bash
python3 -m pip install -e .
threatlint install -y
python3 ~/.claude/scripts/md_to_docx.py report.md report.docx
```

The package declares `python-docx` as a dependency. The converter handles headings,
tables, lists, inline emphasis, and fenced code. It does not execute validation
commands or turn a Mermaid source block into a verified architecture.

Keep the original Markdown when you need diffable review history.

## No Word file

Check the environment and converter:

```bash
python3 -c "import docx; print('python-docx available')"
python3 ~/.claude/scripts/md_to_docx.py
```

With no arguments, the second command prints usage and exits nonzero; that is
expected. If the script or a sibling helper is missing, re-run the installer.
If the library is missing, install Threatlint in that same Python environment.
The direct CLI falls back to Markdown when conversion is unavailable or fails;
inspect the reported saved path.

## Share the decision, not sensitive evidence

Before attaching a report to a ticket or public repository:

1. Remove credentials, tokens, personal data, and customer-specific identifiers.
2. Check that quoted code and architecture may be shared with that audience.
3. Keep the scope, limitations, and validation status with the findings.
4. Link each action to its owner and a measurable acceptance criterion.

**Next:** use [fix verification](agents.md#appsec-verify-fix) to assess remediation,
then execute the relevant tests in an authorized environment.
