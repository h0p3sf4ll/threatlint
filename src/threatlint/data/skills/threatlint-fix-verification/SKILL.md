---
name: threatlint-fix-verification
description: "Use for verifying a security remediation: original exploit reconstruction, fix semantics, equivalent bypass searches, history, regression evidence, and explicit closure verdicts."
---

# Root-cause remediation verification

1. Reconstruct the original finding, actor, input path, sensitive operation, evidence revision,
   and required acceptance criteria. Missing original context limits the verification verdict.
2. Inspect the current implementation and relevant history. Verify the replacement control is
   called, rejects unsafe input on every relevant path, and protects the same asset/tenant.
3. Search adjacent callers, aliases, alternate methods, encodings, role/tenant changes, error
   paths, and fallback behavior for equivalent bypasses. Avoid treating a text match as proof.
4. Distinguish REMEDIATED, PARTIALLY FIXED, STILL PRESENT, and REGRESSED. Regression needs
   historical evidence that a prior effective defense was removed or defeated.
5. Separate static code verification from runtime regression testing. A correct-looking patch
   may support a qualified static verdict, but never claim a test passed without actual output.
6. If closure is incomplete, propose the smallest additional fix and specific regression
   assertions. Do not edit source, run exploit payloads, or authenticate with real credentials.

## Deliverables

VF verdict block with confidence, original/current code evidence, fix/bypass assessment,
remaining assumptions, proposed completion steps, owner/effort, and an acceptance matrix
showing each criterion as Verified, Not Verified, or Not Applicable with supporting evidence.