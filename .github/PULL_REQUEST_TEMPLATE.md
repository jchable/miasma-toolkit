<!-- Thanks for contributing! Keep this a defensive, detection-only toolkit. -->

## What & why

<!-- What does this change do, and which variant / CVE / bug does it address? -->

## Type of change

- [ ] New / updated indicators (`iocs.psd1`)
- [ ] Scanner / hook logic
- [ ] Deobfuscator (`Expand-MiasmaPayload.ps1`)
- [ ] CI guard action / workflow
- [ ] Docs only
- [ ] Other:

## How I tested

<!-- Required. Never test against a live payload — use benign/decoy samples. -->

- [ ] Ran `pwsh -File Scan-Miasma.ps1 -Mode Local` against a throwaway tree and got the expected findings / exit code
- [ ] Exercised affected hooks by piping a crafted JSON payload (see README)
- [ ] `-SelfTest` passes (if the deobfuscator changed)

## Checklist (project conventions)

- [ ] IOCs changed in **`iocs.psd1`** *and* the inline `$IocDefaults` fallback (kept in sync)
- [ ] No indicators hard-coded in a hook
- [ ] Read-only tools stayed read-only; hooks still **quarantine (move), never delete**
- [ ] New IOC-bearing toolkit file added to `Test-MiasmaExcluded`
- [ ] If a category/severity changed: `Add-Finding` regex, README severity list and `CLAUDE.md` agree
- [ ] Both incident reports (`*.en.md` / `*.fr.md`) kept in sync, if touched
- [ ] No personal data / live payload code introduced

<!-- Security vulnerability in the toolkit itself? Do NOT open a PR — see SECURITY.md. -->
