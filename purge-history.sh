#!/usr/bin/env bash
# purge-history.sh — remove Miasma/Shai-Hulud standalone malicious files from ALL git history.
# READ-WRITE / DESTRUCTIVE: rewrites history. Always backs up first; force-push left MANUAL.
#
# Usage:   ./purge-history.sh [repo_path]        (defaults to current dir)
# Tool order: git-filter-repo (preferred)  >  git filter-branch (built-in fallback)
# BFG is intentionally NOT used: its --delete-files matches by basename only, so
# .gemini/settings.json + .claude/settings.json collapse to "settings.json" and it
# would delete EVERY settings.json / setup.js in history (incl. legitimate ones).
# Both tools below are path-scoped and safe.
#
# NOTE: only purges files that are *standalone* worm artifacts. It does NOT purge package.json
#       or Gemfile (legit files with injected content -> fix their content instead, don't drop them).
#       Review/adjust PATHS for your repo before running (.vscode/.claude can be legit elsewhere).
set -euo pipefail

REPO="${1:-$(pwd)}"
cd "$REPO"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repo: $REPO"; exit 1; }

PATHS=(
  ".github/setup.js"
  ".vscode/tasks.json"
  ".cursor/rules/setup.mdc"
  ".gemini/settings.json"
  ".claude/settings.json"
)

echo ">>> 0/4 Backup bundle (full history)"
name="$(basename "$PWD")"
backup="../${name}-backup.bundle"
git bundle create "$backup" --all
echo "    backup -> $backup   (restore: git clone \"$backup\" restored)"

# git-filter-repo removes the 'origin' remote by design; remember it so we can
# restore it afterwards (otherwise the force-push step below would fail).
origin_url="$(git remote get-url origin 2>/dev/null || true)"

echo ">>> 1/4 Rewriting history to drop: ${PATHS[*]}"
if command -v git-filter-repo >/dev/null 2>&1; then
  echo "    using git-filter-repo"
  args=(); for p in "${PATHS[@]}"; do args+=(--path "$p"); done
  git filter-repo --force --invert-paths "${args[@]}"
  if [ -n "$origin_url" ] && ! git remote get-url origin >/dev/null 2>&1; then
    git remote add origin "$origin_url"
    echo "    re-added origin -> $origin_url"
  fi
else
  echo "    using git filter-branch (fallback)"
  export FILTER_BRANCH_SQUELCH_WARNING=1
  rm="git rm -rf --cached --ignore-unmatch"
  for p in "${PATHS[@]}"; do rm="$rm \"$p\""; done
  git filter-branch --force --index-filter "$rm" --prune-empty --tag-name-filter cat -- --all
  git for-each-ref --format='%(refname)' refs/original/ | xargs -n1 git update-ref -d 2>/dev/null || true
  git reflog expire --expire=now --all; git gc --prune=now --aggressive
fi

echo ">>> 2/4 Verification (expect NO output below):"
git log --all --oneline -- "${PATHS[@]}" || true

echo ">>> 3/4 Force-push is DESTRUCTIVE (rewrites public history). Review the verification, then run MANUALLY:"
echo "        git push origin --force --all"
echo "        git push origin --force --tags"
echo ">>> 4/4 Done. After force-push: GitHub may keep old commits by SHA / via PRs -> set repo private"
echo "        and/or contact GitHub Support for a full server-side purge."
