#!/bin/sh
# Fails when organization-identifying text appears in tracked code, a staged change, or a commit message.
# Organization values belong only in environment variables or ~/.threatlint/org.json (see docs/avit-integration.md).
#
#   scripts/check-org-references.sh tree            every tracked file
#   scripts/check-org-references.sh staged          the staged diff (pre-commit)
#   scripts/check-org-references.sh message FILE    a commit message (commit-msg)
#   scripts/check-org-references.sh range A..B      every commit message and diff in a range (CI)
#
# The blocked terms live base64-encoded in .org-blocklist, so neither this script nor that file names an organization.
root=$(git rev-parse --show-toplevel) || exit 2
list="$root/.org-blocklist"
[ -s "$list" ] || exit 0
pattern=$(grep -v -e '^#' -e '^$' "$list" | while read -r line; do printf '%s\n' "$line" | base64 --decode 2>/dev/null || printf '%s\n' "$line" | base64 -D; echo; done | grep -v '^$' | paste -sd'|' -)
[ -n "$pattern" ] || exit 0
fail() { echo "✗ Organization reference found ($1). Move it into an environment variable or ~/.threatlint/org.json." >&2; exit 1; }
case "$1" in
  tree)    git -C "$root" grep -n -I -i -E "$pattern" -- . ':!.org-blocklist' ':!web/node_modules' && fail "tracked files" ;;
  staged)  git -C "$root" diff --cached -U0 -- . ':!.org-blocklist' | grep '^+' | grep -v '^+++' | grep -i -E "$pattern" && fail "staged changes" ;;
  message) grep -v '^#' "$2" | grep -i -E "$pattern" && fail "commit message" ;;
  range)   for commit in $(git -C "$root" rev-list "$2"); do
             git -C "$root" log -1 --format=%B "$commit" | grep -i -q -E "$pattern" && fail "message of $commit"
             git -C "$root" show --format= -U0 "$commit" -- . ':!.org-blocklist' | grep '^+' | grep -i -q -E "$pattern" && fail "diff of $commit"
           done ;;
  *) echo "usage: $0 tree|staged|message FILE|range A..B" >&2; exit 2 ;;
esac
exit 0
