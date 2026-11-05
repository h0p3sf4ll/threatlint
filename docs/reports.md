# Turn a finding into an engineering handoff

A useful security report answers three questions: **what matters, where is the
evidence, and what should we do next?** A file attachment is only the delivery format.

## What to expect

- **Decision first:** risk, scope, priorities, and unresolved uncertainty.
- **Evidence next:** the original finding ID, inspected file/line, attacker path,
  and relevant controls.
- **Action last:** a proposed fix, compatibility notes, suggested owner/effort,
  regression assertions, and acceptance criteria.

False-positive reviews add a disposition and an engineering action plan.
Ambiguous findings stay open with the specific evidence needed to decide.

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
