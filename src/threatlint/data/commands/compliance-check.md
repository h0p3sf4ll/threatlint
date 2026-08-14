---
description: "Map security findings from the most recent report to a named compliance framework. Produces a coverage matrix showing satisfied controls, gaps, and open findings. Saves a Word document."
argument-hint: "Framework to check: OWASP-ASVS, PCI-DSS, HIPAA, SOC2, ISO27001, NIST-CSF, CIS (default: OWASP-ASVS)"
---

Map existing security findings and the current codebase controls to the named compliance framework.

## Steps

Using the Read and Bash tools:

### 1. Identify the framework

From `$ARGUMENTS`, determine the target compliance framework. Supported values:
- `OWASP-ASVS` — OWASP Application Security Verification Standard 4.0
- `PCI-DSS` — PCI DSS v4.0 (focus on requirements 6, 8, 10, 12)
- `HIPAA` — HIPAA Security Rule (focus on 164.312 Technical Safeguards)
- `SOC2` — SOC 2 Type II (focus on Common Criteria: CC6, CC7, CC8, CC9)
- `ISO27001` — ISO/IEC 27001:2022 (Annex A controls)
- `NIST-CSF` — NIST Cybersecurity Framework 2.0 (Identify, Protect, Detect, Respond, Recover)
- `CIS` — CIS Controls v8

Default to `OWASP-ASVS` if blank.

### 2. Read recent reports

Look for recent report files in the current working directory and repository root:
```bash
find . -maxdepth 2 -name "threat-model-*.md" -o -name "security-review-*.md" -o -name "*.docx" 2>/dev/null | sort -r | head -5
```

### 3. Inventory current controls

Read the codebase to identify implemented controls: authentication, authorization, input validation, encryption, logging, secrets management, dependency management.

### 4. Produce the compliance mapping

For each major section of the selected framework, produce a table:

| Control ID | Control Name | Status | Evidence / Finding | Notes |
|------------|-------------|--------|-------------------|-------|
| ASVS 2.1.1 | Verify user passwords are at least 12 chars | ✓ Met | `auth/password.js:42` | bcrypt with cost 12 |
| ASVS 2.1.5 | Verify users can change their password | ✗ Gap | No password change endpoint found | |
| ASVS 4.1.1 | Verify access controls enforced at server | ⚠ Partial | Open finding CR-003 | |

Status values:
- ✓ Met — control is implemented and evidence is found
- ✗ Gap — control is absent or not implemented
- ⚠ Partial — partially implemented or an open finding exists
- N/A — control is not applicable to this system

### 5. Save output

Filename: `<repo-name>-<branch>-compliance-<framework>-YYYY-MM-DD.docx`
Directory: repository root (`git rev-parse --show-toplevel 2>/dev/null || pwd`)

```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
TIMESTAMP=$(date +%s)
```

Write the full report text to `/tmp/compliance_${TIMESTAMP}.md`. Then convert and clean up:
```bash
python3 ~/.claude/scripts/md_to_docx.py /tmp/compliance_${TIMESTAMP}.md "${REPO_ROOT}/${REPO_NAME}-${BRANCH}-compliance-<framework>-YYYY-MM-DD.docx"
rm /tmp/compliance_${TIMESTAMP}.md
```

Report the saved path. Do not modify any repository source files.
