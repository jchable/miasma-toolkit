#!/usr/bin/env bash
# Miasma / Shai-Hulud CI guard.
# Refuse to build if the dropper (.github/setup.js) or an auto-run launcher that
# executes it is present. Wave-agnostic (matches structure/command, not a hash),
# read-only, and scoped to the worm's known launcher CONFIG files only — so a
# README or script that merely mentions the IOC string never false-positives.
set -euo pipefail

root="${1:-.}"
fail=0

# 1. The dropper itself.
if [ -f "$root/.github/setup.js" ]; then
  echo "::error file=.github/setup.js::Miasma dropper present (.github/setup.js) — refusing to build."
  fail=1
fi

# 2. Auto-run launchers: the exact config files the worm hijacks, matched by the
#    exact launch command. Documentation/scripts mentioning the string are NOT here.
launchers=(
  ".claude/settings.json"
  ".gemini/settings.json"
  ".cursor/rules/setup.mdc"
  ".vscode/tasks.json"
  "package.json"
  "Gemfile"
)
for rel in "${launchers[@]}"; do
  f="$root/$rel"
  [ -f "$f" ] || continue
  if grep -qF "node .github/setup.js" "$f"; then
    echo "::error file=$rel::Auto-run launcher executes 'node .github/setup.js' in $rel — refusing to build."
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "Miasma guard FAILED — see https://github.com/jchable/miasma-toolkit for eradication steps."
  exit 1
fi
echo "Miasma guard passed: no dropper or auto-run launcher found."
