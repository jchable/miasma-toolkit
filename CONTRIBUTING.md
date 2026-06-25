# Contributing

Thanks for helping improve the Miasma / Shai-Hulud toolkit. It's a defensive, detection-and-
remediation project — contributions that add coverage for new worm variants, reduce false
positives/negatives, or port the tooling to more platforms are all welcome.

## Ground rules

- **This stays a defensive toolkit.** Detection, triage, and reversible remediation only. PRs that
  add offensive capability, exfiltration, or anything that runs untrusted payloads will be declined.
- Be civil. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) if present.

## Prerequisites

- **PowerShell 7+** (`pwsh`) — required for `Scan-Miasma.ps1` and the `.claude/` hooks.
- **git**; optionally **GitHub CLI** (`gh`), **npm**, **git-filter-repo**, and **YARA** for the
  features that use them (see the README prerequisites table).

## Project conventions (please follow these)

These mirror the design notes in `CLAUDE.md` — the things most likely to bite a new contributor:

1. **`iocs.psd1` is the single source of truth for indicators.** Add or change IOCs there, *never*
   inline in the scanner. The script keeps an inline `$IocDefaults` fallback copy — **update both
   `iocs.psd1` and the matching `$IocDefaults` key** so they stay in sync. The `.claude/` hooks load
   the same `iocs.psd1`; never hard-code indicators in a hook.
2. **Severity is derived from category, not set per finding.** If you add a category, update the
   regex in `Add-Finding`, the README severity list, and `CLAUDE.md` together so they agree.
3. **The read-only tools must stay read-only.** `Scan-Miasma.ps1`, `purge-history.sh` (detection
   parts), and `setup-js.yar` must never modify or delete the files they inspect. The `.claude/`
   hooks are the *only* exception and must **quarantine (move), never hard-delete**.
4. **Keep the hooks' self-exclusion intact.** The toolkit's own files contain IOC strings on
   purpose; `Test-MiasmaExcluded` (in `.claude/hooks/Miasma.Common.ps1`) must keep excluding them,
   or the hooks will quarantine/block the toolkit itself. Add any new IOC-bearing toolkit file to
   that allowlist.
5. **Keep the reports bilingual.** `content/incident-report.en.md` and `incident-report.fr.md` must
   stay in sync — edit both.
6. **Don't regress the documented gotchas** in `CLAUDE.md` / the README (the `gh api` stdout trap,
   the `master`→`main` redirect, `npm audit --package-lock-only` only, the forged-commit heuristic).

## Submitting a change

1. Fork and branch from `main` (e.g. `git checkout -b ioc/new-variant`).
2. Make focused commits with clear messages.
3. **Test on a benign sample**, never a live payload. For scanner changes, run
   `pwsh -File Scan-Miasma.ps1 -Mode Local` against a throwaway tree containing decoy IOC strings
   and confirm the expected findings/exit code. For hook changes, pipe a crafted JSON payload to the
   hook by hand (see the README) and verify quarantine/exclusion behavior.
4. Update docs (README / `CLAUDE.md` / both incident reports) when behavior or IOCs change.
5. Open a PR describing the change, the variant/CVE it covers, and how you tested it.

## Reporting issues

- **Detection gaps / new variants** → open a normal issue or PR against `iocs.psd1`.
- **Security vulnerabilities in the toolkit itself** → follow [SECURITY.md](SECURITY.md)
  (report privately).
