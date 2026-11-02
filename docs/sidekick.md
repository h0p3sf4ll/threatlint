# Make portfolio reviews comparable

A falling finding count can mean improvement—or that this week's report covers
different repositories. Sidekick groups repositories into **loadouts** and keeps
report history so teams can discuss scope, ownership, and progress together.

## Get one useful report

1. Configure the integrations used by your loadout:

   ```bash
   threatlint setup --check
   threatlint ado login --organization YOUR_ORG
   ```

   Save a PAT for each Azure DevOps organization you use. ServiceNow and Semgrep
   share the [AVIT integration settings](avit-integration.md).

2. Set `adoOrganizations` in `~/.threatlint/org.json`, or
   `THREATLINT_ADO_ORGANIZATIONS`, using your own organization names.
3. Open **Sidekick** in the [Workbench](workbench.md), create a loadout, and generate
   a vReport. Use **View vReports** to inspect or download the workbook.

**Success looks like:** the intended repositories appear with their organization,
branch/finding metrics, and ownership context. Inspect failed rows before treating
the workbook as complete.

## Prefer the terminal?

```bash
threatlint sidekick --help
threatlint sidekick loadouts
threatlint sidekick report YOUR_LOADOUT
threatlint sidekick runs --loadout YOUR_LOADOUT
threatlint sidekick trends YOUR_LOADOUT --months 12
```

Each command writes one JSON result to stdout; progress is JSON lines on stderr.
`loadout-save NAME` accepts `repository, project[, organization]` lines on stdin.
Use command help for import, row filtering, stale-branch reports, and retrying
failed rows with `report --only-failed-from RUN_ID`.

## Choose the question before the view

| Question | Use |
| --- | --- |
| Which repositories belong in this review? | Named loadouts or powered loadouts |
| Where are branch and finding concentrations? | vReports and stale-branch reports |
| Who can act on this repository? | Ownership hub; refresh stale cached results |
| Is the portfolio improving on comparable scope? | Trends, including shared-repository comparisons when membership changes |
| What did an operator change? | Actions history |

The ownership cache lasts 14 days. Report failures and scope changes are context,
not evidence that a repository's risk disappeared.

## Bulk operations change real systems

Reporting is not the same as resolution:

- **AVIT closure** writes through ServiceNow's Batch API and journals its actions.
  A recorded closure can be reversed with the corresponding action ID.
- **Bulk triage** ignores matching open Semgrep findings as false positives.
  A broad rule/secret-type selection can affect many findings.
- **History retention** controls available records; do not purge evidence needed
  to explain or reverse an action.

Review the selected scope and reason before confirming. The CLI asks for
confirmation or requires `--yes` in non-interactive use. Do not treat
false-positive analysis as blanket authorization for bulk suppression.

Local data lives under `~/.threatlint/sidekick/` (the equivalent user-profile path
on Windows); `THREATLINT_HOME` can relocate the application home.
Keep exported workbooks and action history out of public commits unless reviewed
for their intended audience.

**Next:** compare a report with a known loadout before enabling bulk actions.
