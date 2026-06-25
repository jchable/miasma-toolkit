# ============================================================================
#  Scan-Write.ps1 — PostToolUse hook (matcher: Write|Edit|MultiEdit).
#
#  After a file is written, re-read it from disk and check it against the IOCs.
#  On a hit: ALERT + move the file to the reversible quarantine vault
#  (.miasma-quarantine/<timestamp>/...). Restore by moving it back; the action
#  is logged to .miasma-quarantine/quarantine.log.
# ============================================================================

. "$PSScriptRoot\Miasma.Common.ps1"

$payload = Read-MiasmaHookInput
if (-not $payload) { exit 0 }

$path = $payload.tool_input.file_path
if (-not $path -and $payload.tool_response) { $path = $payload.tool_response.filePath }
if (-not $path) { exit 0 }
if (Test-MiasmaExcluded -Path $path) { exit 0 }
if (-not (Test-Path -LiteralPath $path)) { exit 0 }

$content = Get-Content -LiteralPath $path -Raw
$hits = Test-MiasmaContent -Path $path -Content $content
if ($hits.Count -eq 0) { exit 0 }

$sigs   = ($hits | ForEach-Object { $_.Sig } | Select-Object -Unique) -join ', '
$reason = "IOC: $sigs"
$dest   = Move-MiasmaToQuarantine -Path $path -Reason $reason

if ($dest) {
    [Console]::Error.WriteLine(
        "MIASMA ALERT - infected file detected and QUARANTINED.`n" +
        "  File:        $path`n" +
        "  Indicators:  $sigs`n" +
        "  Moved to:    $dest`n" +
        "  Logged in:   .miasma-quarantine/quarantine.log`n" +
        "Investigate the source. Restore with: Move-Item '$dest' '$path'  (only if confirmed clean)."
    )
} else {
    [Console]::Error.WriteLine(
        "MIASMA ALERT - infected file detected but COULD NOT be quarantined: $path (indicators: $sigs). " +
        "Quarantine it manually and investigate."
    )
}
exit 2   # surface the alert back to Claude
