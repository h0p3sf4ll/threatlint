---
description: "Security code review using a local model via LM Studio. Analyzes the working-tree diff by default, or a specified branch, commit range, or PR. No API key required."
argument-hint: "Optional: branch, commit range (base..head), PR number, or path (defaults to working-tree diff)"
---

Run an application security code review against the local LM Studio model. No Anthropic, OpenAI, or GitHub credentials are required.

## Routing

Determine the base and head commits from `$ARGUMENTS`:

- Empty / blank: working-tree diff — run `git stash list` and `git status` to understand what is staged and unstaged. Use `git diff HEAD` as the working diff. Set `base` to `HEAD~1` and `head` to `HEAD`, or use the most meaningful base available.
- Commit range (`base..head` or `abc123..def456`): use those SHAs directly.
- Branch name (`main..feature/x`): resolve to SHAs with `git rev-parse`.
- PR number (`42` or `#42`): fetch the diff with `gh pr view 42 --json baseRefOid,headRefOid` to get base and head SHAs.
- Path (`-- src/api`): run `git log --oneline -1 -- <path>` to find the relevant commit, then use HEAD~1..HEAD as the range.

## Steps

Using the Bash tool, run the following in order:

### 1. Verify LM Studio is reachable

```bash
curl -s http://localhost:1234/v1/models
```

If the command fails or returns an empty model list, stop and tell the user: "LM Studio is not running or no model is loaded. Open LM Studio, load a model, and start the local server (Developer > Local Server > Start Server), then retry."

### 2. Resolve base and head SHAs

Use the routing rules above to determine `BASE_SHA` and `HEAD_SHA`.

### 3. Run the security review

```bash
TIMESTAMP=$(date +%s)
python3 ~/.claude/scripts/appsec_api.py \
  --mode pr-review \
  --provider lmstudio \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --output /tmp/cr_local_${TIMESTAMP}.md
```

### 4. Determine output directory and filename

Output directory: the root of the current git repository (`git rev-parse --show-toplevel`), or cwd if not in a git repo.

Resolve repo name and branch:
```bash
REPO_ROOT=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
REPO_NAME=$(basename "$REPO_ROOT" | tr '[:upper:]' '[:lower:]' | tr ' ' '-')
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null | tr '/' '-' | tr '[:upper:]' '[:lower:]')
BRANCH=${BRANCH:-no-branch}
```

Filename (prefix with `${REPO_NAME}-${BRANCH}-`):
- No argument: `<repo-name>-<branch>-security-review-local-YYYY-MM-DD.docx`
- Branch/range: `<repo-name>-<branch>-security-review-local-<sanitized-ref>-YYYY-MM-DD.docx`
- PR number: `<repo-name>-<branch>-security-review-local-pr<N>-YYYY-MM-DD.docx`

### 5. Convert to Word document

```bash
python3 ~/.claude/scripts/md_to_docx.py \
  /tmp/cr_local_${TIMESTAMP}.md \
  <repo-root>/<filename>.docx
rm /tmp/cr_local_${TIMESTAMP}.md
```

### 6. Confirm

Report the full saved path to the user.

If `md_to_docx.py` is not installed, save as `<filename>.md` instead and note that `python-docx` is not installed (`pip3 install python-docx`).

Do not modify any repository source files.
