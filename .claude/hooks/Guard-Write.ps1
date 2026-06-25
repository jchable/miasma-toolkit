# ============================================================================
#  Guard-Write.ps1 — PreToolUse hook (matcher: Write|Edit|MultiEdit).
#
#  Blocks, BEFORE it happens, any write that would inject a Miasma/Shai-Hulud
#  IOC into a file. Prevention beats cleanup. Non-destructive: exit 2 cancels
#  the tool call and feeds the reason back to Claude.
# ============================================================================

. "$PSScriptRoot\Miasma.Common.ps1"

$payload = Read-MiasmaHookInput
if (-not $payload) { exit 0 }

$path = $payload.tool_input.file_path
if (-not $path) { exit 0 }
if (Test-MiasmaExcluded -Path $path) { exit 0 }   # toolkit's own files legitimately hold IOC strings

$content = Get-MiasmaWriteContent -ToolInput $payload.tool_input
$hits = Test-MiasmaContent -Path $path -Content $content
if ($hits.Count -eq 0) { exit 0 }

$sigs = ($hits | ForEach-Object { $_.Sig } | Select-Object -Unique) -join ', '
[Console]::Error.WriteLine(
    "BLOCKED by Miasma guard - this write would inject worm indicator(s) into '$path': $sigs. " +
    "If this is legitimate (e.g. you are editing the detection toolkit itself), add the path to the " +
    "exclusion list in .claude/hooks/Miasma.Common.ps1 (Test-MiasmaExcluded)."
)
exit 2
