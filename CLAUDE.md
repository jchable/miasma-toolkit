# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Incident-response toolkit for the **Miasma** worm (a *Mini Shai-Hulud* variant) that injects
auto-run payloads into AI-agent/IDE configs (`.claude`, `.gemini`, `.cursor`, `.vscode`) and into
npm/GitHub repos, plus coverage for **CVE-2026-35603** (writable `C:\ProgramData` AI-tool configs).
The toolkit is detection + remediation only; there is no application to build and no test suite.
A `.claude/` directory adds **Claude Code hooks** for real-time guard/quarantine on machines that
run Claude Code in this repo (these reuse `iocs.psd1` and are the only components that write/move
files — everything else is read-only).

## Commands

```powershell
# Local scan (defaults to $env:USERPROFILE only — pass -CodeRoots to widen)
pwsh -File Scan-Miasma.ps1 -Mode Local
pwsh -File Scan-Miasma.ps1 -Mode Local -CodeRoots E:\Sources,D:\work

# Remote GitHub scan (gh must be authenticated; auth the TARGET account for private repos/secrets)
gh auth login
pwsh -File Scan-Miasma.ps1 -Mode Remote -Owners jchable,jchable-coderise -OutReport report.md

# Full run with both report formats
pwsh -File Scan-Miasma.ps1 -OutJson findings.json -OutReport report.md
```

Exit code is `1` when any **INFECTED** finding exists (CI-friendly), `0` otherwise.

```bash
./purge-history.sh /path/to/repo        # rewrite git history to drop standalone worm files
yara -r setup-js.yar /path/to/scan      # YARA scan for the dropper/launcher
```

```powershell
# Claude Code hooks run automatically (PreToolUse/PostToolUse/SessionStart). Run a hook by hand:
'{"tool_input":{"file_path":"x.js","content":"getBunPath"}}' | pwsh -File .claude/hooks/Guard-Write.ps1
pwsh -File .claude/hooks/Session-Sweep.ps1     # repo sweep; /miasma-scan wraps Scan-Miasma.ps1
```

## Architecture

- **`Scan-Miasma.ps1`** is the one tool to run. Single file, two scan functions
  (`Invoke-LocalScan`, `Invoke-RemoteScan`) selected by `-Mode Local|Remote|All`. All hits flow
  through `Add-Finding`, which assigns severity by category regex and appends to one `$Findings`
  list; the tail emits the table, optional JSON/Markdown, and the exit code.
- **`iocs.psd1` is the single source of truth for indicators** — edit IOCs here, not in the script.
  It is loaded with `Import-PowerShellDataFile` (pure data, no code execution). The script keeps an
  inline `$IocDefaults` copy as a fallback if the file is missing, and merges any keys absent from
  the loaded file. **When adding/changing an IOC, update `iocs.psd1` AND the matching key in
  `$IocDefaults` so the two stay in sync.** Note: `CmdSigs` is consumed only by the `.claude` Bash
  guard hook (not the scanner) but is mirrored into `$IocDefaults` anyway to keep the two copies
  identical; the hook has its own fallback copy in `Miasma.Common.ps1` too.
- **Severity is derived from category**, not set per-finding: categories `DROPPER, INJECT, FORGED,
  BADDEP, WORKFLOW, RUNNER, PAYLOAD, BUN-DROP, PROGRAMDATA` → `INFECTED`; everything else
  (`NPM-AUDIT, SECRETS, SIGNATURE, PERSIST, PROGRAMDATA-CFG`) → `REVIEW`. The regex in `Add-Finding`
  and the README severity list must agree.
- Local file scan is **one recursive pass per root**; each file is dispatched to every applicable
  rule (don't reintroduce separate `-Recurse` walks). `node_modules` and (for most rules) `.git`
  contents are skipped; size guards keep large files cheap.
- `purge-history.sh` is **destructive**: backs up to a bundle, rewrites history (git-filter-repo
  preferred, `git filter-branch` fallback), and leaves the force-push **manual**. It deliberately
  avoids BFG (basename matching would delete legitimate `settings.json`/`setup.js`) and only purges
  *standalone* artifacts — never `package.json`/`Gemfile` (fix their content instead).
- **`.claude/` hooks** share one helper module (`Miasma.Common.ps1`): `Guard-Write.ps1`
  (`PreToolUse` Write/Edit, blocks IOC-injecting writes via `exit 2`), `Guard-Bash.ps1`
  (`PreToolUse` Bash, blocks worm *execution* — `node .github/setup.js`, `bun`, a piped `bun.sh`
  installer — via `CmdSigs`), `Scan-Write.ps1` (`PostToolUse`, moves infected files to the reversible
  `.miasma-quarantine/` vault), `Session-Sweep.ps1` (`SessionStart`, repo sweep into context), and
  the `/miasma-scan` command. Wired in `.claude/settings.json`. They load IOCs from `iocs.psd1` —
  **never hard-code indicators in a hook.** `CmdSigs` patterns are **anchored to a command position**
  so triage commands that merely *mention* an IOC (`grep`/`yara`/`cat`) are not blocked — only
  execution is.

## Gotchas that bit us (don't regress these)

- `gh api <404> --jq` **prints the error body to stdout**, so output truthiness lies. Always check
  `$LASTEXITCODE` and validate the shape (`FileSize` requires a numeric `^\d+$`, `BranchExists`
  requires the returned name to equal the requested one).
- GitHub keeps a **`master`→`main` redirect** after a rename, so `branches/master` returns 200.
  Only accept a branch when the returned `.name` exactly matches the requested branch.
- npm audit must stay **`--package-lock-only`** — never `npm install`, never run package scripts.
  Lockfiles are written with `[System.IO.File]::WriteAllText` (UTF-8 no BOM) for PS 5.1/7 parity.
- **Forged-commit detection requires more than unsigned + `[skip ci]`** (those occur on legitimate
  commits): it also needs an impersonated github-actions bot email OR a worm message like
  `update dependencies`. Keep `BadEmails` to bot addresses only — never a real owner's email.
- **The hooks must exclude the toolkit's own files** (`Test-MiasmaExcluded`): `iocs.psd1`,
  `Scan-Miasma.ps1`, `purge-history.sh`, `setup-js.yar`, `content/`, `.claude/hooks|commands` all
  contain IOC strings on purpose — without the allowlist the hooks quarantine/block themselves.
  Toolkit dirs are anchored to the repo root (`StartsWith`); only `.git`/`node_modules`/the vault
  match at any depth — so a *user* sub-folder named `content/` is still scanned.

## Conventions

- PowerShell 7+ (`pwsh`) required; `Scan-Miasma.ps1` and the YARA rules are **read-only** (detect,
  never modify/delete). The **`.claude/` hooks are the one exception**: they *move* infected files
  to a reversible, git-ignored quarantine vault (never hard-delete) — keep it that way.
- `$ErrorActionPreference`/`$ProgressPreference` are `SilentlyContinue` by design — failed probes
  must degrade to "no finding," not throw.
- Reports are kept in English and French (`incident-report.en.md` / `incident-report.fr.md`) —
  keep both in sync when editing the write-up.
