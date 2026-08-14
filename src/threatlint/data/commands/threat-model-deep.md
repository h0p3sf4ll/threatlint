---
description: "Deep-dive aggressive threat model with maximum finding coverage. Escalates borderline findings, requires bypass chain analysis for every defensive control, and forces multi-step attack chain exploration. Use for high-value targets, pentest contexts, or when you need exhaustive coverage over conservative precision."
argument-hint: "Optional: component, path, service name, or feature to analyze (leave blank to discover)"
---

Invoke the `appsec-threat-modeler` agent in **aggressive deep-dive mode**.

## Objective

Maximize finding coverage. A missed critical vulnerability is a worse outcome than a false positive that gets triaged away. The agent should operate as a red-team analyst probing for every exploitable path, not a compliance auditor checking boxes.

## Routing

Same as `/threat-model`: discovery mode when `$ARGUMENTS` is blank, focused mode when a target is named.

## Aggressive Analysis Instructions for the Agent

In addition to the standard threat model protocol, the agent must:

### 1. Confidence Escalation
- Default to **PLAUSIBLE** for borderline THEORETICAL/PLAUSIBLE findings when the preconditions are realistic in a production deployment.
- State explicitly which assumption, if confirmed, would promote each PLAUSIBLE finding to CONFIRMED.
- Do not suppress a finding as "edge case" — edge cases are exactly what attackers exploit.

### 2. Control Bypass Analysis
For **every defensive control** discovered in the codebase:
- Authentication middleware, guards, decorators → attempt to enumerate bypass paths (route ordering, HTTP verb confusion, header injection, token reuse)
- Authorization checks → attempt IDOR, privilege escalation, cross-tenant, and HTTP method bypass paths
- Input validation and sanitization → attempt encoding bypasses, boundary conditions, and alternate representations
- Rate limiting and anti-abuse controls → attempt distribution, header spoofing, and identifier rotation
- Document each bypass attempt and its outcome (feasible / not feasible / requires runtime confirmation)

### 3. Attack Chain Construction
- Do not model vulnerabilities in isolation. For every CONFIRMED or PLAUSIBLE finding, determine whether it enables or amplifies any other finding.
- Construct chained attack paths that combine two or more findings into a higher-impact scenario.
- Show the full kill chain: initial foothold → privilege escalation → lateral movement → data access or persistence.

### 4. Coverage Breadth Requirements
The threat register must include at least one evaluated finding (even if THEORETICAL or CLEAN) for each applicable category: injection, authentication, authorization, secrets/credentials, cryptography, error handling/info disclosure, CI/CD/supply chain, infrastructure/configuration.

If a category has no findings, document explicitly: "No findings — [specific reason tied to the reviewed code]."

### 5. Attacker Assumptions
- Treat the attacker as having full knowledge of the source code, dependencies, configuration structure, and deployment architecture.
- Treat the attacker as patient and well-resourced — capable of chaining low-probability steps.
- Do not downgrade a finding because it "requires internals knowledge" or "is hard to discover."

### 6. Runtime Blindspot Inventory
For every critical security decision deferred to runtime (environment variables, config files, cloud IAM policies, secrets managers), produce an explicit **Runtime Blindspot** entry in Residual Risk that names what would need to be verified out-of-band and what a misconfiguration would enable.

## Required Output

Same two-tier format as `/threat-model` (including the document header with repo name, date, and scope), plus:
- A **Control Bypass Analysis** subsection in Tier 2 documenting every control examined and its bypass status.
- A **Chained Attack Scenarios** subsection in Tier 2 presenting multi-step kill chains.
- A **Coverage Audit** line at the end of Tier 2 confirming which categories were evaluated and which (if any) were excluded with justification.
- Every finding must include a **Remediation Guidance** block with numbered, codebase-specific steps and before/after code snippets where applicable, followed by a **Validation** step.
- **Suggested Focused Follow-Ups** as the final section.

Do not modify the workspace.

## Output: Save as Word Document

After the agent delivers its report, save the full report to a Word document:

1. **Determine the output directory.**
   - If `$ARGUMENTS` is an existing file path: use its parent directory.
   - If `$ARGUMENTS` is an existing directory path: use that directory.
   - Otherwise (component name, service name, or blank): use the current working directory.

2. **Choose a filename** — prefix with `<repo-name>-<branch>-` where `<repo-name>` is the lowercased basename of the repo root (spaces → hyphens) and `<branch>` is the current branch name (lowercased, `/` → `-`). Derive them with:
   ```
   REPO_NAME=$(basename "$(git rev-parse --show-toplevel 2>/dev/null || pwd)" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
   BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
   BRANCH=${BRANCH:-no-branch}
   ```
   - No target argument: `<repo-name>-<branch>-threat-model-deep-YYYY-MM-DD.docx`
   - Named target: `<repo-name>-<branch>-threat-model-deep-<sanitized-target>-YYYY-MM-DD.docx` (lowercase, spaces → hyphens, strip slashes)
   - Use today's date.

3. **Convert to Word document** by running these shell steps:
   ```
   # Write markdown to a temp file
   Write the full report text to /tmp/tm_report_<timestamp>.md

   # Convert using the helper script
   python3 ~/.claude/scripts/md_to_docx.py /tmp/tm_report_<timestamp>.md <output-dir>/<filename>.docx

   # Remove the temp file
   rm /tmp/tm_report_<timestamp>.md
   ```

4. **Confirm** the saved path to the user once the file is written.
