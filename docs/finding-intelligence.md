# Understand repository risk from connected evidence

Open a workspace, run a security scan, then choose **Repository risk**. **Refresh
evidence** also imports that workspace's saved specialist reports. Select a branch
or revision to inspect the actual observed scope. Historical reports without
revision metadata remain **unknown**; they never inherit today's checkout.

Scanner results begin as unreviewed leads. Expand **Review evidence and record a
decision**, inspect the source and callers yourself, and record the new evidence,
verification method, decision basis, and limits. The attestation records your
review; this action does not execute a test or independently validate a quote.
Reported severity and confidence remain visible separately from disposition.

## Connect an attack path

1. Review every vulnerability contributor as **TRUE POSITIVE**. A contextual
   contributor also needs verified evidence. Select two or more findings from
   the same repository, branch, commit, and working-tree content digest.
2. Open **Build an evidence-backed exploit chain**. Order the findings, describe
   each prerequisite-to-effect transition, and select its verified evidence.
3. Add a reviewed evidence record with purpose **Observed terminal impact** to
   the final finding. Select that record and explain the impact severity,
   complexity, reviewed coverage, and remaining uncertainties.
4. Save the reviewed chain. Its component findings, severities, evidence, and
   immutable decision histories remain available.

A connected, acyclic path with one terminal effect is required. Different
branches, commits, unknown revisions, disconnected collections, unsupported
edges, and unverified vulnerability contributors are rejected. Three medium
findings remain three medium findings unless the reviewer independently assesses
and supports a different terminal impact. There is no automatic CVSS calculation
or arithmetic promotion from component severities.

The chain also has a separate, transparent **contextual priority** rubric:
terminal-impact weight (Critical 10, High 6, Medium 3, Low 1) multiplied by
reviewed complexity (low 1, moderate 0.75, high 0.5). Bands are Critical at 9 or
above, High at 4.5, Medium at 2, and Low below 2. The following matrix shows the
resulting priority band and points out of 10:

| Terminal impact | Low complexity | Moderate complexity | High complexity |
| --- | --- | --- | --- |
| Critical | Critical · 10 | High · 7.5 | High · 5 |
| High | High · 6 | High · 4.5 | Medium · 3 |
| Medium | Medium · 3 | Medium · 2.25 | Low · 1.5 |
| Low | Low · 1 | Low · 0.75 | Low · 0.5 |

This local triage heuristic helps order reviewed paths while preserving severe
terminal impact: difficulty changes priority, not the consequence if the attack
succeeds. It is not a calibrated likelihood estimate or CVSS. Any recorded
uncertainty makes the priority **provisional** and never increases its points.
It never suppresses a finding, alters a component, or automatically resolves a
path. The interface and ServiceNow preview retain the impact, complexity,
formula, rationale, and provisional status together.

A standalone false positive may supply **context** while retaining that original
decision. It cannot be treated as a vulnerability contributor. Reopening a false
positive requires substantively new verified evidence that explicitly refutes
the original decision basis and is cited in the new basis. Relabeling the old
quote, changing a verification-method label, model agreement, and proximity to
another finding do not qualify. The new chain's **CHAIN TRUE POSITIVE** disposition
does not overwrite any component's standalone disposition.

When a component's decision changes, an existing chain is marked
**needs-reassessment** and its ServiceNow preview is blocked. Chains for older
observed revisions are labeled **historical-revision**.

## Read progress conservatively

Repository risk and Metrics show recorded open findings, verified remediations,
coverage, and priority points over time. Missing results—even in a scan labeled
complete for its declared scope—never prove a finding is resolved. A verified
remediation decision reduces the count; an occurrence on a later revision opens
independently. Findings not reobserved in the latest scan remain visible.

Priority points use a transparent ordinal rubric: Critical 10, High 6, Medium 3,
Low 1, Info/unspecified 0. They are **not CVSS**, and composite assessments are
not added again to the component total. Trends retain the evidence ledger's
observed scope; they are not a claim that two different engines or revisions
provide equivalent coverage. Unknown revision observations stay isolated in the
ledger; the default overview selects the latest observation of each logical
issue on each branch. Use the revision filter to inspect earlier observations.
Unknown engine severities are explicitly unscored rather than treated as low
risk. Conflicting severity observations remain in history; each time point uses
the highest severity observed for that occurrence up to that time.

## Preview integrations

**Download ServiceNow preview** exports a proposed parent composite, related
findings, work notes, evidence references, and stable idempotency keys. It makes
no network request to ServiceNow and creates no records. An eventual connector
must validate instance tables/fields and implement authenticated upserts using
the supplied parent and component keys. Repeated previews produce the same
payload for unchanged evidence. Raw source quotes are omitted from the related
record export; inspect the preview's descriptions and work notes before sharing.

Metrics includes an optional **Private developer coaching** preview. It requires
personal opt-in and explicit verified introduction evidence for each included
issue. Commit authorship does not establish responsibility. Enter the actual
number of reviewed changes, including changes without findings, and record
evidence for known exposure. A minimum of five reviewed changes and one eligible
issue is needed for a numerical preview. This stub stores no identities or
scores, compares no employees, and supports no employee ranking.

The coaching priority index is:

`min(100, round(10 × Σ(severity × exposure × recurrence × remediation) / reviewed changes))`

Severity uses the rubric above. Exposure is 1.5 for verified internet exposure,
1 for internal or unknown, and 0.75 for local. A repeated verified rule across
distinct logical issues gets 1.25; otherwise recurrence is 1. Verified
remediation reduces its factor to 0.25. Unknown exposure is neutral and lowers
confidence. Duplicate observations never increase the numerator. The preview
shows every factor, exclusions, sample size, confidence, limitations, and
code-specific improvement steps. Its subject label, supplied sample, coverage,
and reviewer attestations are not independently verified population data.

## Integration contract

The local single-user server applies its existing same-origin loopback guard.
Every intelligence route requires an existing workspace `sessionId`; repository
identity is resolved from that session and cannot be overridden in an HTTP
ingestion. Manual imports are labeled `imported`, even if a caller claims a
different origin. Evidence quotes and review fields are rendered as text.

| Endpoint | Purpose |
| --- | --- |
| `GET /api/intelligence/overview?sessionId=...` | Current summary, all revision observations, branches, chains, and trends |
| `POST /api/intelligence/sync` | Ingest saved workspace reports without guessing their provenance |
| `POST /api/intelligence/ingestions` | Import normalized findings into the session's repository |
| `GET /api/intelligence/findings/:id?sessionId=...` | One revision-bound finding and immutable review history |
| `POST /api/intelligence/findings/:id/reviews` | Record an explicit evidence-backed decision |
| `POST /api/intelligence/composites` | Validate and save a reviewed attack graph |
| `GET /api/intelligence/composites/:id?sessionId=...` | Inspect the saved graph |
| `POST /api/intelligence/composites/:id/servicenow-preview` | Offline parent/related-record export preview |
| `POST /api/intelligence/developer-risk-preview` | Opt-in, nonpersistent private coaching calculation |

POST bodies include `sessionId`. The scanner completion integration is:

```js
const { createFindingIntelligenceStore, ingestionFromScan } = require('./lib/finding-intelligence.cjs');
const intelligence = createFindingIntelligenceStore({ directory });
intelligence.ingest(ingestionFromScan(scan, session));
```

An ingestion contains `repo: {id, name}`, `branch`, `commit`, `contentDigest`,
`source`, `sourceId`, `observedAt`, `coverage: {status, scope, limitations}`, and
`findings`. A finding contains `id`, `ruleId`, optional provider `fingerprint`,
`title`, `severity`, `confidence`, `category`, `recommendation`, and evidence
records `{path, line, quote}` or source references. Scanner-style
`{path, line, snippet}` and saved-report `path:line` strings are supported.

Identity is deterministic and scoped to repository, engine namespace, rule, and
provider fingerprint (or normalized title/location fallback). Occurrence IDs
also bind branch, commit, and content digest. Unknown revision/content metadata
additionally binds the observation's source ID. Different tools are not merged
on title resemblance. Repeated ingestion of the same source revision is
idempotent; changing its content is rejected. Use a new source ID for new
observations. Changed fallback line locations can split an issue until a stable
provider fingerprint or explicit evidence correlation is available.

A review body is shaped as follows. Evidence indices refer to this request's
`newEvidence` array; existing evidence IDs can also be cited.

```json
{
  "sessionId": "workspace-id",
  "disposition": "TRUE POSITIVE",
  "reason": "The inspected caller reaches the data access without ownership validation.",
  "newEvidence": [{
    "path": "src/orders.js",
    "line": 42,
    "quote": "return orderStore.get(request.params.id);",
    "kind": "source",
    "verification": "verified",
    "verificationMethod": "Inspected this route and its authentication middleware at the bound revision."
  }],
  "basis": [{"claim": "The caller does not validate order ownership.", "evidenceIds": [0]}]
}
```

False-positive decisions also need `safeBehavior`. To reopen a closed decision,
the new evidence's `refutes` points to an original `reviewHistory[].basis[].id`.
Remediation decisions require new verified evidence with `kind: "remediation"`;
record the actual fixed revision/test artifact in its reference and verification
method. The finding provenance identifies the occurrence under review, and must
not be mistaken for the fixed revision. No test is marked executed by the API.

A composite contains `title`, `contributors: [{findingId, role, rationale}]`,
`links: [{prerequisite, effect, rationale, evidenceIds}]`,
`impact: {severity, description, evidenceIds}`, `complexity: {level, rationale}`,
`riskRationale`, `coverage`, and `uncertainty: []`. Roles are `vulnerability` or
`context`; complexity is `low`, `moderate`, or `high`. Impact evidence must belong
to the terminal finding and have `kind: "impact"`.

The ledger is stored in `finding-intelligence.json` alongside Workbench state
using an atomic replacement and mode 0600. Reads return detached copies;
ingestion and review actions retain history. This is a local audit trail, not a
tamper-evident external compliance log. No dependency installation or customer
data is needed for its tests:

```bash
node --test web/tests/finding-intelligence.test.cjs web/tests/finding-intelligence-ui.test.cjs
node web/tests/finding-intelligence-browser-smoke.cjs
```

The browser check runs the actual UI and local server against clearly labeled
synthetic ledger data. It verifies reviewer attestation, supported and rejected
FP reopening, explicit chain construction, preview download, and insufficient
coaching data. Set `THREATLINT_BROWSER_EXECUTABLE` when needed; on macOS it can use
the installed Google Chrome. No model provider or tracker is contacted.
