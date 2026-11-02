"""Snapshot instructions for findings mapping, change tracking, and fix verification."""

COMPLIANCE_CHECK_SYSTEM = (
    'You are an expert security compliance engineer with deep knowledge of OWASP ASVS 4.0, '
    'PCI-DSS v4.0, HIPAA Security Rule, SOC 2 Type II, ISO 27001:2022, NIST CSF 2.0, and CIS Controls v8. '
    'Map every provided security finding to one or more specific controls in each applicable framework. '
    'For each control, state: control ID, control text, finding that triggers it, current status '
    '(FAILED / PARTIAL / PASSED / NOT APPLICABLE), and the remediation action required. '
    'Produce a per-framework compliance gap table and an overall compliance posture summary.'
)

COMPLIANCE_CHECK_TEMPLATE = '''\
{target_line}

## Repository Context / Prior Findings

{context}

## Required Report Format

Produce a two-tier Markdown compliance mapping report.

### TIER 1 — EXECUTIVE SUMMARY

**Overall Compliance Posture**: HIGH RISK / MEDIUM RISK / LOW RISK / COMPLIANT

One-sentence summary.

**Framework Coverage**:
| Framework | Controls Checked | Failed | Partial | Passed | N/A |
|-----------|-----------------|--------|---------|--------|-----|
| OWASP ASVS 4.0 | | | | | |
| PCI-DSS v4.0 | | | | | |
| HIPAA Security Rule | | | | | |
| SOC 2 Type II | | | | | |
| ISO 27001:2022 | | | | | |
| NIST CSF 2.0 | | | | | |
| CIS Controls v8 | | | | | |

**Top Compliance Gaps** (FAILED controls with CRITICAL or HIGH findings):
- **[Framework § Control]** *Title* — finding driving the gap. Required action.

---

### TIER 2 — CONTROL-BY-CONTROL MAPPING

For each finding, map to applicable frameworks:

#### Finding: [Finding ID or Description]

| Framework | Control ID | Control Text | Status | Gap / Remediation |
|-----------|-----------|--------------|--------|-------------------|
| OWASP ASVS | V?.?.? | | FAILED/PARTIAL/PASSED | |
| PCI-DSS | Req ?.? | | | |
| HIPAA | § 164.3?? | | | |
| SOC 2 | CC?.? | | | |
| ISO 27001 | A.?? | | | |
| NIST CSF | [Function].[Category].[Subcategory] | | | |
| CIS Controls | Control ?.? | | | |

---

**Remediation Priority by Framework**:
| Priority | Framework | Control | Severity | Effort |
|----------|-----------|---------|----------|--------|
'''

THREAT_DELTA_SYSTEM = (
    'You are an expert application security engineer performing a threat-delta analysis. '
    'Compare the provided prior security report against the current repository state. '
    'For each finding in the prior report, classify it as: '
    'RESOLVED (fix confirmed in code), PARTIALLY FIXED (control added but bypass exists), '
    'STILL PRESENT (no meaningful change), REGRESSED (was fixed, now re-introduced), '
    'WONT FIX / ACCEPTED (documented exception), or CANT ASSESS (insufficient evidence). '
    'Also identify NEW findings present in the current code that were absent from the prior report. '
    'Ground every verdict in specific code evidence. Label all assumptions explicitly.'
)

THREAT_DELTA_TEMPLATE = '''\
{target_line}

## Current Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown threat-delta report comparing the prior report to current state.

### TIER 1 — DELTA SUMMARY

**Net Risk Change**: INCREASED / DECREASED / UNCHANGED

**Finding Delta**:
| Verdict | Count |
|---------|-------|
| RESOLVED | |
| PARTIALLY FIXED | |
| STILL PRESENT | |
| REGRESSED | |
| NEW | |
| WONT FIX / ACCEPTED | |
| CANT ASSESS | |

**Key Changes** (Regressed and New findings only):
- **[ID]** *Title* — what changed and why it matters.

---

### TIER 2 — FINDING-BY-FINDING DELTA

For each finding from the prior report:

#### [Prior ID] — *Finding Title*

**Prior Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Verdict**: RESOLVED / PARTIALLY FIXED / STILL PRESENT / REGRESSED / WONT FIX / CANT ASSESS

| Field | Detail |
|-------|--------|
| Prior Evidence | original `path/to/file:NN` |
| Current State | what the code looks like now |
| Evidence | `path/to/file:NN` — quoted current code |
| Rationale | why this verdict was assigned |
| Remaining Risk | if PARTIALLY FIXED: remaining bypass path |

---

### NEW FINDINGS

Findings present in the current code not in the prior report:

#### [NEW-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Evidence | `path/to/file:NN` |
| Introduced By | commit hash or change description if determinable |
| Remediation | |

---

**Updated Remediation Roadmap**:
| Priority | ID | Title | Verdict | Action Required |
|----------|----|-------|---------|-----------------|
'''

VERIFY_FIX_SYSTEM = (
    'You are an expert application security engineer performing fix verification. '
    'Given a specific finding (ID, title, description, and original evidence location), '
    'verify whether the fix has been applied correctly in the current codebase. '
    'Return one of four verdicts: '
    'REMEDIATED (fix present, no equivalent bypass), '
    'PARTIALLY FIXED (fix present but at least one equivalent exploit path remains), '
    'STILL PRESENT (no meaningful change from the original finding), or '
    'REGRESSED (fix was present in a prior version but has been removed or weakened). '
    'Cite exact file:line evidence for the verdict. Be conservative: '
    'only return REMEDIATED when the fix is verifiably correct and no bypass exists.'
)

VERIFY_FIX_TEMPLATE = '''\
Finding to verify:
- **ID**: {finding_id}
- **Title**: {finding_title}
- **Original Evidence**: {finding_evidence}
- **Description**: {finding_description}

## Current Repository Context

{context}

## Required Report Format

Produce a concise fix-verification report.

### VERDICT: REMEDIATED / PARTIALLY FIXED / STILL PRESENT / REGRESSED

**Verdict**: (one of the four above)

**Confidence**: CONFIRMED / PLAUSIBLE

### Evidence

| Field | Detail |
|-------|--------|
| Original Location | `path/to/file:NN` |
| Current Code | quoted current code at that location |
| Fix Applied | yes / no / partial |
| Equivalent Bypass | if PARTIALLY FIXED: describe the remaining attack path |
| Regression Evidence | if REGRESSED: what was removed or weakened |

### Rationale

2–4 sentences explaining the verdict, citing specific code evidence.

### Recommended Next Step

One sentence: what the developer should do (if not REMEDIATED).
'''
