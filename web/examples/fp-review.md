# False Positive Review: Example Payments API

**Status**: SYNTHETIC EXAMPLE — not an analysis of your repository
**Date**: 2026-10-17
**Input**: Illustrative scanner findings and source excerpts
**Scanner**: Example SAST export; original rule definition unavailable
**Scan / current revision**: Not applicable; fictional demonstration
**Scope**: Two illustrative database-query findings
**Findings reviewed**: 2
**Reviewed by**: appsec-fp-reviewer

## TIER 1 — EXECUTIVE SUMMARY

The example contains one genuine query-construction defect and one incorrectly flagged parameterized
query. Engineering should prioritize the vulnerable query. The false-positive verdict does not authorize
a scanner suppression: the original rule and a representative regression corpus are still required.
All paths and excerpts below are fictional. No tests, scans, or code changes were performed.

### Finding Summary

| Disposition | Count |
| --- | --- |
| TRUE POSITIVE | 1 |
| FALSE POSITIVE | 1 |
| AMBIGUOUS | 0 |

Input: 2; unique: 2; duplicates: 0; reviewed: 2; unreviewed: 0.

### Priority Actions

| Priority | Finding / original ID | Action | Suggested owner | Effort | Acceptance |
| --- | --- | --- | --- | --- | --- |
| P1 | FP-001 / scanner-17 | Bind the identifier rather than interpolate it into SQL | API engineering | Small, one function plus tests | Query text stays constant for all input |
| P2 | FP-002 / scanner-18 | Obtain the original rule and test a narrow exclusion | Scanner owner | Small to medium | Proven-safe query is quiet; unsafe near-misses still detected |

## TIER 2 — DETAILED FINDINGS

#### [FP-001] — Customer lookup builds SQL from request input

**Original finding**: scanner-17; example.sql-query-construction
**Disposition**: TRUE POSITIVE
**Severity**: HIGH
**Confidence**: CONFIRMED
**Owner**: API engineering (suggested)
**Effort**: Small; one query and focused regression tests

**Finding and impact**: In this fictional SQLite handler, a request-controlled identifier becomes
part of SQL syntax rather than a bound value. Authentication does not prevent a legitimate user
from manipulating that value. The query must preserve both authorization and data/value separation.

**Evidence**: Fictional `example/api/customers.py:41-44`:

```python
customer_id = request.args["id"]
query = f"SELECT id, name FROM customers WHERE id = '{customer_id}'"
row = connection.execute(query).fetchone()
```

| Stage | Evidence and interpretation |
| --- | --- |
| Source | example/api/customers.py:41 — request argument is caller-controlled |
| Transform | example/api/customers.py:42 — formatting changes the SQL program text |
| Control | No parameter binding in this illustrative path |
| Sink | example/api/customers.py:43 — the assembled text is executed |

**Assessment and alternative interpretation**: A read-only lookup is not necessarily harmless:
altering predicates can change which records are returned. An upstream identifier validator is not
shown in this example. Parameter binding addresses the demonstrated query-construction defect;
tenant/object authorization must still be enforced separately.

### Proposed Fix

**PROPOSED — NOT APPLIED**, using Python SQLite parameter binding:

```diff
-query = f"SELECT id, name FROM customers WHERE id = '{customer_id}'"
-row = connection.execute(query).fetchone()
+query = "SELECT id, name FROM customers WHERE id = ?"
+row = connection.execute(query, (customer_id,)).fetchone()
```

**Implementation Notes**: The placeholder syntax is SQLite-specific; use the actual database driver's
binding API in a real project. Retain the tenant predicate and ownership check if present. No schema
migration is expected for this example. Do not roll back to interpolation if another compatibility
issue appears; use a forward correction or temporarily disable the affected operation.

### Regression Tests

**NOT RUN**. Using an isolated SQLite fixture, verify that a known identifier returns only its expected
row; an unknown identifier returns no row; punctuation and SQL-looking values remain literal values;
and cross-tenant requests are rejected by the authorization layer. Assert the SQL statement is constant
and the supplied identifier is passed separately as a bound parameter.

**Acceptance Criteria**: Code review confirms binding on every equivalent lookup path; the positive,
negative, and tenant-isolation tests pass; and the original scanner finding is re-evaluated against
the patched revision. A suggested patch alone is not closure evidence.

#### [FP-002] — Scanner flags a query that already binds the identifier

**Original finding**: scanner-18; example.sql-query-construction
**Disposition**: FALSE POSITIVE
**Severity**: INFO
**Confidence**: CONFIRMED
**Owner**: Scanner configuration team (suggested)
**Effort**: Small to medium; original rule and corpus review are prerequisites

**Evidence**: Fictional `example/api/orders.py:25-28`:

```python
order_id = request.args["id"]
row = connection.execute(
    "SELECT id, total FROM orders WHERE id = ?", (order_id,)
).fetchone()
```

**Verified Safe Behavior**: In the illustrated SQLite API, the statement is constant and the identifier
is a bound value. The scanner's query-injection claim is not supported on this path. This verdict does
not establish object-level authorization, which is outside the illustrative finding's claim.

### Proposed Tuning

**Exact rule required**. Do not invent a replacement from the scanner message. Obtain the original
rule, its language/mode, and scanner version. Propose the narrowest constraint that distinguishes a
constant statement plus real parameter binding from dynamically constructed statement text.

**Coverage and Blast Radius**: No suppression is approved. A blanket exclusion for `execute()` or
the API directory would also hide genuine defects such as FP-001. The proposed distinction must
retain detection of concatenation, formatting, unsafe wrappers, and mismatched placeholder usage.

### Rule Regression Tests

**NOT RUN**. Once the original rule is available, create fixtures with the exact same rule ID:

```python
# ok: example.sql-query-construction
connection.execute("SELECT id FROM orders WHERE id = ?", (order_id,))

# ruleid: example.sql-query-construction
connection.execute(f"SELECT id FROM orders WHERE id = '{order_id}'")
```

These are illustrative fixture expectations, not a validated Semgrep rule. Include unsafe wrapper,
alias, and near-miss variants, then run rule validation and the fixture corpus with the actual engine.

**Approval and Rollback**: The scanner owner must review the original rule and executed tests before
approval. Restore the prior rule if known unsafe fixtures disappear or a new false negative is found.
Re-evaluate the exception when the rule, driver, or wrapper semantics change.

## TIER 3 — ENGINEERING ACTION PLAN

### Suppression Impact Assessment

| Proposal | Scope | TPs retained | Potential false negatives | Validation | Approval |
| --- | --- | --- | --- | --- | --- |
| FP-002 rule constraint | Only proven parameter-bound calls, pending rule review | Must include FP-001 and unsafe near-misses | Overbroad wrapper or placeholder assumptions | NOT RUN | Blocked on original rule and regression corpus |

### Systemic Root Causes

The application defect is the mixing of SQL syntax and data; use driver-native binding consistently.
The scanner symptom may be an imprecise match, but its exact cause cannot be established without
the original rule. These are separate engineering tasks with separate acceptance criteria.

### Remediation Roadmap and Acceptance Matrix

| Order | Action | Suggested owner | Acceptance evidence | Status |
| --- | --- | --- | --- | --- |
| 1 | Implement FP-001 binding proposal in a reviewed change | API engineering | Reviewed patch and regression output | NOT RUN |
| 2 | Obtain original rule/version and a representative fixture corpus | Scanner owner | Rule artifact and documented expectations | Blocked |
| 3 | Review a narrow FP-002 rule proposal | Scanner owner + AppSec | Engine validation and retained TP detections | NOT RUN |

### Limitations and Open Questions

This is a synthetic report preview, not real security evidence. No source repository was inspected,
no scanner ran, and no proposal was applied. A real review must establish source/scan revision
alignment, driver behavior, callers, authorization, and rule semantics before accepting these decisions.