# <img src="media/logo.svg" alt="" width="28" height="31" align="top"> Metrics and dashboards

Find the next investigation without rereading every report. **Metrics** groups saved findings
and current-session runtime observations by severity, workspace, specialist, and time.
A workspace bar chart shows where reported HIGH findings cluster; inspect those reports before assigning work.

[Watch the walkthrough](../web/public/media/dashboards.mp4), or use **Learn & videos** in the app.

![Metrics dashboard](media/dashboards.png)

## First useful view

1. [Run a review](workbench.md#review-experience) so the Workbench has a saved report.
2. Open **Metrics → Security posture** and choose a **Time range**: all, 7, 30, or 90 days.
3. Inspect severity and workspace charts. Use hover/focus values or **Table** on supported charts.

**Expected result:** retained evidence counts, not a fresh scan. Build a release view below.

## The built-in dashboard

*Security posture* is read-only; **Customize** creates an editable copy.

| Widget | How to interpret it |
| --- | --- |
| Open risk score | Sum of weights excluding FALSE POSITIVE, REMEDIATED, RESOLVED: CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1, INFO 0, unspecified 1 |
| Findings | Parsed finding count; repeated reports can count the same issue again |
| Evidence coverage % | Findings with parsed evidence references; runtime observations count as evidenced. Not proof evidence is correct |
| Reports & scans | Distinct reports and runtime scans |
| Findings by severity / over time | Severity distribution and report/scan dates—not verified remediation progress |
| Risk by specialist / workspace | Weighted open findings grouped by specialist or workspace label |
| Specialist × severity | Finding counts; darker cells mean more findings |

Workspace labels use repository basenames or runtime target URLs; identical basenames can
share a label. Scores prioritize reported evidence, not validated exploitability.

## Build your own

1. Choose **New dashboard**, **Duplicate**, or **Customize**. Name it, e.g. `API release review`.
2. **Add widget**; choose metric, grouping, chart, width, and optional severity filter.
3. For heatmaps choose **Columns** too. Reorder with ↑ / ↓, remove with ×.
4. **Save dashboard** and select it from the dashboard menu.

**Result:** a layout saved locally in `dashboards.json` beside history.

| Choice | Available values |
| --- | --- |
| Metric | `findings`, `riskScore`, `uniqueFindings` (fingerprint deduplication), `evidenceCoverage`, `reports` |
| Group by | `severity`, `agent`, `category`, `workspace`, `day`, `week`, `disposition`, `confidence`, `source`, `rule` |
| Chart | Stat tile, column, bar, line, donut, table, heatmap |
| Size | Small (¼ row), medium (½), full width |

Heatmaps always show **finding counts**. Severity colors are fixed; other entity colors stay stable.

### Recipes

| Question | Metric | Group by | Chart / filter |
| --- | --- | --- | --- |
| Where are HIGH findings? | findings | workspace | Bar; HIGH (add another widget for CRITICAL) |
| What did triage decide? | findings | disposition | Donut |
| How much weighted risk did each specialist report? | riskScore | agent | Bar |
| What was reported each week? | findings | week | Line |
| Which workspace/severity combinations dominate? | findings | workspace | Heatmap; columns = severity |

## Export and API

**Export CSV** includes all retained rows—not the dashboard/time filter—with timestamp, source,
workspace, agent/category, ID, title, severity, confidence, disposition, and evidence flag.
Formula-like prefixes are escaped. Treat exports as sensitive.

With the browser Workbench running on its default port:

```bash
curl -s http://127.0.0.1:3000/api/metrics/overview
curl -s http://127.0.0.1:3000/api/metrics/schema
curl -s http://127.0.0.1:3000/api/metrics/query -H 'Content-Type: application/json' \
  -d '{"metric":"riskScore","groupBy":"workspace","filters":{"severity":"HIGH","source":"report"}}'
```

Filters: `severity`, `agent` (ID), `category`, `workspace`, `source` (`report` / `runtime`),
`disposition`, `since` (ISO date). The API checks browser origins; do not expose it publicly.

## Limits

Reports persist; the last 25 runtime scans disappear on restart. `uniqueFindings` deduplicates
fingerprints, not verified vulnerabilities. Report volume, scope, or model changes can move charts
without code changes. Calculations stay local; reviews may send source to your provider.

## Troubleshooting

| Symptom | Next action |
| --- | --- |
| Empty charts | Save a report, check the selected time range, then reopen Metrics |
| Counts seem duplicated | Compare report dates/IDs; use `uniqueFindings` where appropriate |
| Runtime counts disappeared | Restart clears session scans; export evidence before stopping |
| Cannot edit Security posture | Choose **Customize** to save a copy |
| CSV differs from visible chart | CSV exports all retained findings; apply filters in your analysis |

Next: [turn findings into an engineering handoff](reports.md).
