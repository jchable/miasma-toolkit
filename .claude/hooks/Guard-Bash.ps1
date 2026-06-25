# ============================================================================
#  Guard-Bash.ps1 — PreToolUse hook (matcher: Bash).
#
#  The worm executes via COMMANDS, not only files: `node .github/setup.js`, the
#  `bun` runtime, or a piped `bun.sh` installer. This hook inspects the command
#  the Bash tool is about to run and BLOCKS it (exit 2) if it matches a worm
#  execution pattern. The patterns (iocs.psd1 -> CmdSigs) are anchored to a
#  command position, so triage commands that merely MENTION an IOC
#  (grep/yara/cat over the toolkit) are not blocked.
# ============================================================================

. "$PSScriptRoot\Miasma.Common.ps1"

$payload = Read-MiasmaHookInput
if (-not $payload) { exit 0 }

$cmd = $payload.tool_input.command
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

$hits = Test-MiasmaCommand -Command $cmd
if ($hits.Count -eq 0) { exit 0 }

$sigs = ($hits | ForEach-Object { $_.Sig } | Select-Object -Unique) -join ' | '
[Console]::Error.WriteLine(
    "BLOCKED by Miasma guard - this command looks like worm execution: $sigs`n" +
    "Miasma launches via 'node .github/setup.js', the 'bun' runtime, or a piped 'bun.sh' installer. " +
    "If this is genuinely legitimate, run it outside Claude Code or adjust CmdSigs in iocs.psd1."
)
exit 2
