# ============================================================================
#  Session-Sweep.ps1 — SessionStart hook.
#
#  Fast, repo-scoped sweep run at the start of each Claude Code session. Walks
#  the project once (skipping excluded paths + large files) and checks each file
#  against the IOCs. Prints a short report to stdout, which Claude Code adds to
#  the session context, so any pre-existing infection is surfaced before work.
#
#  This sweep is read-only (alert only). Active files are caught/quarantined by
#  Scan-Write.ps1 as they are written. For a full local + remote scan use
#  Scan-Miasma.ps1 (or the /miasma-scan command).
# ============================================================================

. "$PSScriptRoot\Miasma.Common.ps1"

$root = Get-MiasmaProjectDir
$maxBytes = 2MB
$findings = @()

Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Length -le $maxBytes } |
    ForEach-Object {
        if (Test-MiasmaExcluded -Path $_.FullName) { return }
        $c = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { return }
        $hits = Test-MiasmaContent -Path $_.FullName -Content $c
        if ($hits.Count -gt 0) {
            $sigs = ($hits | ForEach-Object { $_.Sig } | Select-Object -Unique) -join ', '
            $findings += "  [INFECTED] $($_.FullName)  ->  $sigs"
        }
    }

if ($findings.Count -gt 0) {
    Write-Output "MIASMA SESSION SWEEP - $($findings.Count) suspicious file(s) found in this repo:"
    $findings | ForEach-Object { Write-Output $_ }
    Write-Output "Run /miasma-scan (or Scan-Miasma.ps1) for full triage. Do NOT execute these files."
} else {
    Write-Output "Miasma session sweep: repo clean (no IOC matches)."
}
exit 0
