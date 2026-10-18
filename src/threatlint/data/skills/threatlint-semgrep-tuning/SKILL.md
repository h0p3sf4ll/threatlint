---
name: threatlint-semgrep-tuning
description: "Use when proposing Semgrep false-positive tuning: original rule analysis, narrow pattern constraints, contextual taint sanitizers, ruleid/ok regression fixtures, suppression blast radius and rollback."
---

# Coverage-preserving Semgrep proposals

1. Obtain the original complete rule, its language/mode, rule ID, scanner version, and relevant
   matching semantics. If unavailable, do not invent an exact replacement rule; describe the
   minimal desired constraint and label any example **ILLUSTRATIVE — NOT VALIDATED**.
2. Prefer the narrowest correct rule constraint over broad path exclusions or inline suppressions.
   Show a full replacement rule or an anchored diff preserving original metadata and semantics.
   Explain why the exclusion matches only the proven-safe case and where it might overmatch.
3. Taint sanitizers must be appropriate to the specific sink context, on the same value, and
   effective on every relevant path. Trimming, variable names, authentication, and HTML escaping
   in a shell/SQL/JavaScript context are not generic sanitizers. Avoid broad wrapper-name trust.
4. Treat `.semgrepignore` as scan-wide path suppression, not a single-rule exclusion. Generated,
   vendor, test, and migration code may still be security-relevant; require verified deployment
   boundaries and explicit owner acceptance. Prefer narrower rule-scoped paths when possible.
5. Inline suppression requires the exact rule ID, rationale, owner, review/expiry condition,
   and an explicit trade-off. Never modify source or scanner configuration yourself.
6. Propose fixtures using `# ruleid: exact-rule-id` / `# ok: exact-rule-id` (or language-appropriate
   comments). Include the observed FP, a close TP, sanitizer bypass, alternate argument/alias,
   and unsafe near-miss. Test expectations must match the rule, not a made-up counting API.
7. Specify `semgrep --validate --config <rule>` and `semgrep --test --config <rule> <fixtures>`
   as **NOT RUN** unless actual results exist. YAML parsing alone does not validate Semgrep
   syntax, version compatibility, rule semantics, or coverage preservation.

## Approval and rollback

For each proposal state affected IDs, patterns/paths suppressed, known TPs retained,
potential false negatives, validation status, reviewer/owner, and rollback trigger.
Never invent coverage percentages or promise zero TP loss without a representative executed
corpus. An FP verdict can stand while its proposed suppression remains unapproved.