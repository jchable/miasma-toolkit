---
description: Run the Miasma / Shai-Hulud scanner and triage findings
allowed-tools: Bash(pwsh:*)
---

Run the Miasma incident-response scanner on this machine and summarize the result.

Steps:
1. Run the local scan, scoped to this repo plus the user profile:
   `pwsh -NoProfile -File "$CLAUDE_PROJECT_DIR/Scan-Miasma.ps1" -Mode Local $ARGUMENTS`
   - To widen coverage, the user can pass extra args, e.g. `/miasma-scan -CodeRoots E:\Sources,D:\work`.
   - For a remote GitHub scan: `/miasma-scan -Mode Remote -Owners <owner1>,<owner2>` (requires `gh auth login`).
2. Report every **INFECTED** finding first (these set exit code 1), then **REVIEW** findings.
3. For each INFECTED hit, state the file/category and the recommended remediation
   (do NOT execute any suspicious file). Reference `content/incident-report.*.md` for the playbook.
4. Note any files already moved to `.miasma-quarantine/` by the write hooks.

Do not modify or delete anything yourself — the scanner and this command are read-only triage.
