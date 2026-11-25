---
title: Review findings
description: Verify scanner findings, record review decisions, and inspect repository risk over time.
---

# Review findings

Use **Repository risk** to bring scanner results and saved specialist reports into one review. Findings begin as unreviewed leads. A severity label or model recommendation does not establish that an issue is exploitable.

## Load the evidence

1. Open the repository workspace and run a [source scan](security-scanner.md), or complete a specialist review.
2. Open **Repository risk** and choose **Refresh evidence** to include saved reports.
3. Select the branch or revision you want to inspect. Confirm its coverage and limitations before reviewing findings.

Historical reports without revision metadata remain **unknown**; they do not inherit the current checkout. The selected revision scopes finding cards, connected attack paths, and Repository risk history. **Metrics** retains the workspace's history across observed branches.

## Record a decision

1. Expand **Review evidence and record a decision** on a finding.
2. Inspect the source, relevant callers, and cited evidence at the recorded revision.
3. Add the evidence you verified, how you verified it, and the basis for your decision.
4. Choose the appropriate disposition and save the review.

A false-positive decision requires evidence of safe behavior. A remediation decision requires new verified remediation evidence identifying the actual fix or test artifact. Recording an attestation does not execute a test or independently validate a quotation.

Severity, confidence, and disposition remain separate. Review history is retained. To reopen a false positive, provide substantively new verified evidence that refutes its original decision basis; relabeling an old quote or obtaining model agreement is insufficient.

## Connect an attack path

Advanced mode lets you build an evidence-backed exploit chain when individual findings form a connected path:

1. Review every vulnerability contributor as **TRUE POSITIVE**. Contextual contributors also need verified evidence.
2. Select at least two findings from the same repository, branch, commit, and working-tree content digest.
3. Open **Build an evidence-backed exploit chain**. Order the findings and describe each prerequisite-to-effect transition, citing verified evidence.
4. Add an **Observed terminal impact** evidence record to the final finding. Assess its severity, complexity, coverage, and uncertainty.
5. Save the reviewed chain and inspect its component assessments and directional links.

The chain must be connected, acyclic, and have one terminal effect. Unknown or mixed revisions and unsupported transitions are rejected. Three medium findings do not automatically become a high finding. Terminal impact needs its own supporting evidence; component severities and standalone decisions remain intact.

A false positive can supply context while retaining that decision, but cannot become a vulnerability contributor. If a component's decision changes, the chain becomes **needs-reassessment** and its ServiceNow preview is blocked. Older chains remain **historical-revision**, even when you select that revision.

The displayed **contextual priority** uses terminal-impact weight multiplied by reviewed complexity. It is a local triage rubric, not CVSS or a calibrated likelihood estimate. Difficulty affects priority, not the assessed consequence. Recorded uncertainty makes the priority provisional.

## Read progress conservatively

Repository risk and Metrics show recorded open findings, verified remediations, coverage, and priority points. Missing results do not prove resolution, including when a scan completed for its declared scope. Findings not reobserved remain visible; a later occurrence opens independently.

Verified false positives close an issue but do not count as verified remediations. Priority points are ordinal: Critical 10, High 6, Medium 3, Low 1, and Info or unspecified 0. Unknown engine severities remain unscored. Connected chains are not added again to component totals.

Compare revisions and engines alongside their coverage. Two scans need not cover equivalent code or rules. Use the revision filter to inspect earlier observations rather than treating a trend as a complete security assessment.

## Preview integrations

**Download ServiceNow preview** exports proposed parent and related records, work notes, evidence references, and stable record keys. It makes no ServiceNow request and creates no records. Review the exported descriptions and notes before sharing; raw source quotations are omitted from related records.

**Private developer coaching** in Metrics is an optional, personal preview. It needs opt-in, verified introduction evidence, at least five reviewed changes, and one eligible issue for a numerical result. Commit authorship alone does not establish responsibility. Include reviewed changes without findings in the sample.

The preview shows its factors, exclusions, confidence, and limitations. It stores no identities or scores and provides no employee comparison or ranking. Changing inputs, refreshing evidence, or withdrawing consent clears the assessment. It is not an independently verified measure of a person's work.

For remote tracker actions, see [Manage connections and tickets](integrations.md). For saved review output, see [Reports and exports](reports.md).
