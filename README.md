# Miasma / Shai-Hulud toolkit

Incident analysis + detection/remediation tooling for the **Miasma** worm (a *Mini Shai-Hulud*
variant) that injects auto-run payloads into AI-agent / IDE configs and npm/GitHub repos.

## Contents

| File | What it is |
|---|---|
| `content/incident-report.fr.md` / `content/incident-report.en.md` | Full write-up: how it works, payload deobfuscation, IOCs, eradication |
| **`Scan-Miasma.ps1`** | **Unified scanner** (local + remote), structured JSON + Markdown report — *use this* |
| `iocs.psd1` | Shared indicators (hashes, signatures, bad packages, configs) loaded by the scanner — *edit IOCs here* |
| `purge-history.sh` | Purge malicious files from **all git history** (filter-repo → filter-branch) + backup |
| `setup-js.yar` | YARA rules for the dropper + launcher configs |
| `.claude/` | **Claude Code hooks** — real-time guard/quarantine + `/miasma-scan` command (see below) |

## Prerequisites

| Tool | Needed for | Required? |
|---|---|---|
| **PowerShell 7+** (`pwsh`) | `Scan-Miasma.ps1` | required |
| **git** | local-repo history checks, `purge-history.sh` | required |
| **GitHub CLI** (`gh`, authenticated) | `Scan-Miasma.ps1 -Mode Remote` | remote scan only |
| **npm** | remote `npm audit` (lockfile-only) | optional (auto-skipped if absent) |
| **git-filter-repo** | preferred history rewrite (falls back to built-in `git filter-branch`) | optional |
| **YARA** (`yara`) | `setup-js.yar` scan | optional |

Install YARA (Windows): `winget install VirusTotal.YARA` — or `choco install yara` / `scoop install yara`.
On Linux/macOS: `apt install yara` / `brew install yara`. Verify with `yara --version`.

## Quick usage

> Note: `-Mode Local` defaults to scanning `$env:USERPROFILE` only. Pass `-CodeRoots` to cover
> repos elsewhere, e.g. `-CodeRoots E:\Sources,D:\work`.

```powershell
# Scan local machine + local repos (+ CVE-2026-35603 ProgramData)
pwsh -File Scan-Miasma.ps1 -Mode Local
pwsh -File Scan-Miasma.ps1 -Mode Local -CodeRoots E:\Sources,D:\work

# Scan remote GitHub repos (authenticate on the target account first for private repos/secrets)
gh auth login
pwsh -File Scan-Miasma.ps1 -Mode Remote -Owners your-org,your-user -OutReport report.md

# Everything + JSON + Markdown report
pwsh -File Scan-Miasma.ps1 -OutJson findings.json -OutReport report.md
```
Exit code `1` if any **INFECTED** finding (CI-friendly).

```bash
# Purge history of an infected repo (review PATHS in the script first)
./purge-history.sh /path/to/repo
# then, after reviewing the verification:
git push origin --force --all && git push origin --force --tags
```

```bash
# YARA scan
yara -r setup-js.yar /path/to/scan
```

## CI guard (drop into a GitHub Actions workflow, first step)

```yaml
- name: Block Miasma/Shai-Hulud dropper
  shell: bash
  run: |
    if [ -f .github/setup.js ] || \
       grep -rqsI "node .github/setup.js" .claude .gemini .cursor .vscode package.json Gemfile 2>/dev/null; then
      echo "::error::Miasma/Shai-Hulud dropper or launcher detected — failing build"; exit 1
    fi
```

## Claude Code hooks (`.claude/`)

Real-time protection for machines that run **Claude Code** in this repo. The hooks reuse
`iocs.psd1` (no duplicated indicators) and are wired in `.claude/settings.json`:

| Hook | Event | Action |
|---|---|---|
| `Guard-Write.ps1` | `PreToolUse` (Write/Edit/MultiEdit) | **Blocks** a write that would inject a worm IOC (cancels the tool call) |
| `Guard-Bash.ps1` | `PreToolUse` (Bash) | **Blocks** worm *execution* — `node .github/setup.js`, `bun`/`bunx`, a piped `bun.sh` installer |
| `Scan-Write.ps1` | `PostToolUse` (Write/Edit/MultiEdit) | **Alerts + quarantines** an infected file after it lands |
| `Session-Sweep.ps1` | `SessionStart` | Fast repo sweep; reports any pre-existing infection into context |
| `/miasma-scan` | command | On-demand wrapper around `Scan-Miasma.ps1` |

- **Quarantine is reversible**: infected files are *moved* to `.miasma-quarantine/<timestamp>/…`
  (git-ignored) and logged to `.miasma-quarantine/quarantine.log` — restore with `Move-Item`.
  Nothing is hard-deleted.
- **Self-exclusion** (`Test-MiasmaExcluded` in `Miasma.Common.ps1`): the toolkit's own files
  legitimately contain IOC strings (`iocs.psd1`, `Scan-Miasma.ps1`, `purge-history.sh`,
  `setup-js.yar`, `content/`, `.claude/hooks|commands`) and are never blocked/quarantined.
- **`Guard-Bash` targets execution, not mention**: its patterns (`iocs.psd1` → `CmdSigs`) are
  anchored to a command position, so triage commands that merely name an IOC
  (`grep "node .github/setup.js"`, `yara -r setup-js.yar`, `cat setup.js`) are **not** blocked —
  only actually running `node …/setup.js` / `bun` / a `bun.sh` install pipe is. Note: `bun`/`bunx`
  invocation is blocked outright (the worm's runtime); allowlist via `CmdSigs` if you genuinely need Bun.
- ⚠️ Unlike `Scan-Miasma.ps1` (read-only), these hooks **modify the tree** (quarantine). They are
  opt-in: Claude Code prompts to approve hooks the first time it loads `.claude/settings.json`.

## Severity model (Scan-Miasma.ps1)

- **INFECTED** — `DROPPER`, `INJECT`, `FORGED`, `BADDEP`, `WORKFLOW`, `RUNNER`, `PAYLOAD`, `BUN-DROP`, `PROGRAMDATA`
- **REVIEW** — `NPM-AUDIT`, `SECRETS` (rotation inventory), `SIGNATURE`, `PERSIST`, `PROGRAMDATA-CFG`

## Known bugs already fixed (keep in mind when reworking)

- `gh api <404> --jq` **dumps the error body to stdout** → never trust output truthiness;
  check `$LASTEXITCODE` + validate the format (numeric size, exact branch name).
- GitHub keeps a **`master`→`main` redirect** after rename → `branches/master` returns 200;
  only accept a branch if the **returned name == requested name**.
- npm audit must stay **`--package-lock-only`** (no `npm install`, no scripts executed).

## TODO / rework backlog

1. Bash port of the local scan (Linux/macOS dev machines).
2. Static deobfuscator (char codes → Caesar → AES-GCM) to extract the `_p` stealer's C2.
3. Richer report (per-repo Markdown, severity badges).
4. Package the CI guard as a reusable composite action.
5. Auto-rotation helpers (gh/aws/npm token revoke checklist).

## References

- *The bot that never was* — icflorescu (dev.to)
- *Miasma worm: AI coding agent config injection* — safedep.io
- *CVE-2026-35603: AI coding tools privilege escalation* — Cymulate
