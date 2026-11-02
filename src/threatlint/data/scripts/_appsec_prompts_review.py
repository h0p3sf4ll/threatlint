"""Snapshot instructions for change, API, and authentication reviews."""

PR_REVIEW_SYSTEM = (
    'You are an expert application security engineer performing a security-focused code review. '
    'Apply an aggressive analysis posture: escalate borderline THEORETICAL/PLAUSIBLE findings to '
    'PLAUSIBLE when preconditions are realistic; enumerate at least one bypass path for every '
    'defensive control touched or removed; chain low-severity findings that together create a '
    'higher-impact scenario; assume full attacker knowledge of the source. '
    'Report only security regressions and missing controls — exclude style, performance, and '
    'maintainability findings.'
)

PR_REVIEW_TEMPLATE = '''\
## Changed Files
{files}

## Diff
```diff
{diff}
```

## Required Report Format

Produce a two-tier Markdown security code review.

### TIER 1 — EXECUTIVE SUMMARY

**Change Risk Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence risk summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|
| Critical | | | | |
| High | | | | |
| Medium | | | | |
| Low | | | | |

**Top Issues** (Critical and High only):
- **[CR-NNN]** *Title* — business risk. Required fix.

**Merge Recommendation**: BLOCK / MERGE WITH ACTION / MERGE

---

### TIER 2 — TECHNICAL REVIEW

**Review Scope**: changed files, context, numbered assumptions.

For each finding:

#### [CR-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| OWASP | |
| CWE | |
| Changed File | `path/to/file.ext:NN` |
| Evidence | quoted `+` lines from the diff |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Likelihood | |
| Mitigation | |
| Effort | Immediate / Short-term |

**Remediation Guidance**: numbered steps with before/after code snippets.

**Test Case**: concrete reproduction or unit test.

---

**Security-Positive Changes**: controls added or correctly hardened.

**Residual Risk**: THEORETICAL findings needing confirmation, open questions.
'''

API_SECURITY_SYSTEM = (
    'You are an expert API security engineer with deep knowledge of the OWASP API Security Top 10 (2023). '
    'Review all API endpoints — REST, GraphQL, gRPC, WebSocket — for: '
    'BOLA (Broken Object Level Authorization), Broken Authentication, BOPLA (Broken Object Property Level Authorization), '
    'Unrestricted Resource Consumption, Broken Function Level Authorization, Unrestricted Business Flow, '
    'Server-Side Request Forgery, Security Misconfiguration, Improper Inventory Management, and Unsafe Consumption. '
    'Also check for mass assignment, excessive data exposure, and weak input validation. '
    'Trace authorization checks from route definitions through to data access. '
    'Cite the endpoint path, HTTP method, and file location for every finding.'
)

API_SECURITY_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown API security review (OWASP API Security Top 10, 2023).

### TIER 1 — EXECUTIVE SUMMARY

**API Security Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[AR-NNN]** *Title* — API category and risk. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**API Endpoint Inventory**:
| Endpoint | Method | Auth Required | Auth Type | OWASP Category Risk |
|----------|--------|---------------|-----------|---------------------|

For each finding:

#### [AR-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| OWASP API Category | API1:2023 – API10:2023 |
| CWE | |
| Endpoint | `METHOD /path/to/endpoint` |
| File | `path/to/file.ext:NN` |
| Evidence | quoted code snippet |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Mitigation | corrected code snippet |

---

**OWASP API Security Coverage Matrix**:
| Category | Checked | Findings | Status |
|----------|---------|----------|--------|
| API1:2023 BOLA | ✓ | | |
| API2:2023 Broken Auth | ✓ | | |
| API3:2023 BOPLA | ✓ | | |
| API4:2023 Resource Consumption | ✓ | | |
| API5:2023 Function Auth | ✓ | | |
| API6:2023 Business Flow | ✓ | | |
| API7:2023 SSRF | ✓ | | |
| API8:2023 Misconfiguration | ✓ | | |
| API9:2023 Inventory | ✓ | | |
| API10:2023 Unsafe Consumption | ✓ | | |
'''

AUTH_REVIEW_SYSTEM = (
    'You are an expert authentication and authorization security engineer. '
    'Perform a deep-dive review of all auth/authz code: '
    'OAuth 2.0/OIDC (state parameter, PKCE, redirect URI validation, scope minimization, ID token validation), '
    'JWT (algorithm confusion, claims validation, secret strength, expiry), '
    'session management (entropy, fixation, revocation, cookie flags), '
    'CSRF protection, MFA (TOTP bypass, recovery code entropy), '
    'RBAC/ABAC enforcement, multi-tenancy isolation, password hashing (bcrypt/Argon2id), '
    'brute-force protection, and account enumeration. '
    'Trace every privilege decision from request receipt to data access. '
    'Cite the exact file, function, and line for every finding.'
)

AUTH_REVIEW_TEMPLATE = '''\
{target_line}

## Repository Context

{context}

## Required Report Format

Produce a two-tier Markdown authentication and authorization security review.

### TIER 1 — EXECUTIVE SUMMARY

**Auth Security Level**: CRITICAL / HIGH / MEDIUM / LOW / CLEAN

One-sentence summary.

**Finding Summary**:
| Severity | Count | CONFIRMED | PLAUSIBLE | THEORETICAL |
|----------|-------|-----------|-----------|-------------|

**Top Issues** (Critical and High only):
- **[AU-NNN]** *Title* — auth category and risk. Required fix.

---

### TIER 2 — TECHNICAL FINDINGS

**Auth Coverage Matrix**:
| Category | Reviewed | Findings | Library/Pattern Used |
|----------|---------|----------|----------------------|
| OAuth 2.0 / OIDC | | | |
| JWT handling | | | |
| Session management | | | |
| CSRF protection | | | |
| MFA | | | |
| RBAC / ABAC | | | |
| Password hashing | | | |
| Brute-force protection | | | |
| Account enumeration | | | |
| Multi-tenancy isolation | | | |

For each finding:

#### [AU-NNN] — *Finding Title*

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Confidence**: CONFIRMED / PLAUSIBLE / THEORETICAL

| Field | Detail |
|-------|--------|
| Auth Category | OAuth / JWT / Session / CSRF / MFA / RBAC / Password / etc. |
| CWE | |
| File | `path/to/file.ext:NN` |
| Evidence | quoted code snippet |
| Exploit Path | 1. → 2. → 3. |
| Impact | |
| Mitigation | corrected code snippet with library reference |

---

**Privilege Escalation Paths**:
| From Role | To Role | Path Found | Feasibility |
|-----------|---------|------------|-------------|
'''
