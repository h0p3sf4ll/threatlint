# Finding Review: contoso-ledger (Example_Project)

**Date**: 2026-11-26

## TIER 1 — EXECUTIVE SUMMARY

**Risk and decision**: AVIT000000000000001 is a confirmed SQL injection.

## TIER 2 — FINDINGS

#### [FP-001] — SQL injection in LedgerController.Index: request region is formatted into SQL text through a static field
**Original finding**: AVIT000000000000001; csharp.dotnet-core.sqli.systemdata-taint.systemdata-taint; Semgrep Code; webApp/Contoso_Ledger_LATEST_PROD/Controllers/LedgerController.cs:96
**Disposition**: TRUE POSITIVE
**Confidence**: CONFIRMED.
**Decision basis**: Supported by inspected evidence (not a conservative default)
**Severity**: CRITICAL (my own assessment)
**Owner**: Ledger web application engineering team (suggested, not an agreed owner)
**Effort**: About 0.5 engineer-day. The fix touches six call sites in one controller.

**Finding and impact**:

**The rule's claim.** A non-numeric parameter of a public action reaches a System.Data.SqlClient sink without passing through any of the rule's sanitisers. The inspected code meets every condition:
- The source file has `using Microsoft.AspNetCore.Mvc;` (line 3).

**Impact.** A single quote ends the literal. From there an attacker can add predicates, UNION queries or stacked statements to the batch, which runs as the SQL login loaded from Key Vault (lines 39–54; values not inspected).
- That login can write: the same controller runs UPDATE and INSERT on ledger tables (lines 378–428).
- One malicious request also affects later requests from other users because the value is stored in a static field.

**Severity rationale.** The action is reachable without authentication in the checked-in configuration.

**Evidence** (checkout `abc1234`; short excerpts, credential values redacted):
`webApp/Contoso_Ledger_LATEST_PROD/Controllers/LedgerController.cs:93-96`:
```csharp
string queryMapping = String.Format("select * from [dbo].[Mapping] where RegionName = '{0}'", SelectedRegion);
using (SqlCommand command = new SqlCommand(queryMapping, conn))
adapter = new SqlDataAdapter(command);
```

**Assessment and alternative interpretation**:
- "Region values come from a fixed UI list." There is no server-side allowlist. A crafted request bypasses any client-side list. Rejected.

**Proposed Fix** (direction only; the complete patch is **PROPOSED — NOT APPLIED** and belongs to the separate fix step): Use constant SQL with `@region` bound as `SqlDbType.NVarChar` at lines 87, 93, 100, 205 and 211.

Before (vulnerable):
```csharp
string queryMapping = String.Format("select * from [dbo].[Mapping] where RegionName = '{0}'", SelectedRegion);
using (SqlCommand command = new SqlCommand(queryMapping, conn))
```

After:
```csharp
const string queryMapping = "select * from [dbo].[Mapping] where RegionName = @region";
using (SqlCommand command = new SqlCommand(queryMapping, conn))
{
    command.Parameters.Add("@region", SqlDbType.NVarChar).Value = (object)region ?? DBNull.Value;
}
```

**Implementation Notes**:
- Fix all six statements, not just line 96.
- Binding a null as an empty string keeps the current comparison.

**Acceptance Criteria**:
- No SQL in LedgerController.cs is built from SelectedRegion by formatting, interpolation or concatenation.
- The regression tests pass in CI, and the owner attaches the log.
- A Semgrep re-scan of the branch is clean at line 96 and at the sibling lines.

**Regression Tests** (all **NOT RUN**; they need a new xUnit project):
1. Attack rejection: for `x' OR '1'='1`, a stacked payload and a delay payload, CommandText equals the constant SQL and the payload appears only as the value of `@region`.
2. Allowed success: a known region returns the same rows as before the change.
3. Boundary: a null region returns the empty view without running SQL.
