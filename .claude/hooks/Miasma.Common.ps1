# ============================================================================
#  Miasma.Common.ps1 — shared helpers for the Claude Code Miasma hooks.
#
#  Single source of truth for indicators stays iocs.psd1 (loaded here). These
#  hooks REUSE that data; they never hard-code IOCs. Detection logic mirrors the
#  lightweight content checks in Scan-Miasma.ps1 (ContentSigs / WfSig / SHA-256).
#
#  Dot-source this file from each hook:  . "$PSScriptRoot\Miasma.Common.ps1"
# ============================================================================

$ErrorActionPreference = 'SilentlyContinue'  # failed probes must degrade, never throw (toolkit convention)
$ProgressPreference    = 'SilentlyContinue'

function Get-MiasmaProjectDir {
    if ($env:CLAUDE_PROJECT_DIR) { return $env:CLAUDE_PROJECT_DIR }
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

function Get-MiasmaIoc {
    $root = Get-MiasmaProjectDir
    $psd1 = Join-Path $root 'iocs.psd1'
    if (Test-Path $psd1) {
        $data = Import-PowerShellDataFile -Path $psd1
        if ($data) { return $data }
    }
    # Minimal fallback so the hook still protects if iocs.psd1 is missing.
    return @{
        PayloadShas = @()
        ContentSigs = @('.github/setup.js','getBunPath','oven-sh/bun','detectHardenRunner',
                         '.sshu-setup','createCommitOnBranch','Runner.Worker','169.254.169.254','typeof Bun')
        WfSig       = 'setup\.js|oven-sh|bun\.sh/install|node \.github|curl -fsSL https://bun|getBunPath'
        CmdSigs     = @(
            '(^|[;&|(]|&&|\|\|)\s*(node|nodejs)\b[^|;&]*\bsetup\.js\b',
            '(^|[;&|(]|&&|\|\|)\s*bunx?\b',
            '(^|[;&|(]|&&|\|\|)\s*(curl|wget)\b[^|;&]*\bbun(\.sh)?\b',
            '\b(sh|bash|zsh|dash)\s+-c\s+[''"]?\s*(node|nodejs)\b[^''"]*\bsetup\.js\b'
        )
    }
}

# Paths the hooks must NEVER quarantine/block: the detection toolkit's own files
# legitimately contain IOC strings, plus VCS / deps / the quarantine vault itself.
function Test-MiasmaExcluded {
    param([Parameter(Mandatory)][string]$Path)

    $root = (Get-MiasmaProjectDir).TrimEnd('\','/')
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { $full = $Path }
    $full = $full.Replace('/', '\')

    # Relative path inside the project (or the full path if outside).
    $rel = $full
    if ($full.ToLower().StartsWith(($root + '\').ToLower())) {
        $rel = $full.Substring($root.Length + 1)
    }
    $relL = $rel.ToLower()

    # Skipped at ANY depth (VCS / deps / the vault itself can be nested).
    $skipAnywhere = @('.git\', 'node_modules\', '.miasma-quarantine\')
    foreach ($d in $skipAnywhere) { if ($relL.StartsWith($d) -or $relL -like "*\$d*") { return $true } }

    # Toolkit's own dirs — anchored to the repo root only, so a same-named
    # sub-folder inside a scanned project is NOT wrongly skipped.
    $skipTopLevel = @('.claude\hooks\', '.claude\commands\', 'content\')
    foreach ($d in $skipTopLevel) { if ($relL.StartsWith($d)) { return $true } }

    $excludedFiles = @('iocs.psd1', 'scan-miasma.ps1', 'setup-js.yar', 'purge-history.sh',
                       'readme.md', 'claude.md', '.claude\settings.json')
    foreach ($f in $excludedFiles) { if ($relL -eq $f) { return $true } }

    return $false
}

# Returns an array of @{ Sig=...; Category=... } for every IOC matched in $Content.
function Test-MiasmaContent {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Content
    )
    $ioc  = Get-MiasmaIoc
    $hits = @()
    if ([string]::IsNullOrEmpty($Content)) { return $hits }

    # Literal worm body / loader signatures.
    foreach ($sig in $ioc.ContentSigs) {
        if ($Content.IndexOf($sig, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $hits += @{ Sig = $sig; Category = 'PAYLOAD' }
        }
    }
    # Injected-workflow / launcher regex.
    if ($ioc.WfSig -and $Content -match $ioc.WfSig) {
        $hits += @{ Sig = "regex:$($Matches[0])"; Category = 'INJECT' }
    }
    # Known dropper SHA-256 (hash the candidate content as UTF-8, no BOM).
    if ($ioc.PayloadShas -and $ioc.PayloadShas.Count -gt 0) {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
        $sha   = [System.Security.Cryptography.SHA256]::Create()
        $hash  = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToUpper()
        $sha.Dispose()
        if ($ioc.PayloadShas -contains $hash) {
            $hits += @{ Sig = "sha256:$hash"; Category = 'DROPPER' }
        }
    }
    return $hits
}

# Returns an array of @{ Sig=...; Pattern=... } for every worm-execution pattern
# matched in a shell command. Patterns are anchored to a command position, so
# merely mentioning an IOC (grep/yara/cat during triage) does NOT match.
function Test-MiasmaCommand {
    param([string]$Command)
    $ioc  = Get-MiasmaIoc
    $hits = @()
    if ([string]::IsNullOrWhiteSpace($Command)) { return $hits }
    if (-not $ioc.CmdSigs) { return $hits }
    foreach ($rx in $ioc.CmdSigs) {
        if ($Command -match $rx) { $hits += @{ Sig = $Matches[0].Trim(); Pattern = $rx } }
    }
    return $hits
}

# Move an infected file into the reversible quarantine vault and log it.
# Returns the quarantine destination path, or $null on failure.
function Move-MiasmaToQuarantine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$Reason = ''
    )
    $root = Get-MiasmaProjectDir
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full)) { return $null }

    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $rel   = $full
    if ($full.ToLower().StartsWith(($root.TrimEnd('\') + '\').ToLower())) {
        $rel = $full.Substring($root.TrimEnd('\').Length + 1)
    } else {
        $rel = Split-Path $full -Leaf   # outside project: keep just the filename
    }

    $vault = Join-Path $root ".miasma-quarantine\$stamp"
    $dest  = Join-Path $vault $rel
    $destDir = Split-Path $dest -Parent
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    Move-Item -LiteralPath $full -Destination $dest -Force
    if (-not (Test-Path -LiteralPath $dest)) { return $null }

    $logLine = '{0}  QUARANTINED  {1}  ->  {2}  [{3}]' -f $stamp, $full, $dest, $Reason
    $logFile = Join-Path $root '.miasma-quarantine\quarantine.log'
    Add-Content -LiteralPath $logFile -Value $logLine -Encoding UTF8
    return $dest
}

# Read the hook's stdin JSON payload (Claude Code passes tool data this way).
function Read-MiasmaHookInput {
    $raw = [Console]::In.ReadToEnd()
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    try { return ($raw | ConvertFrom-Json) } catch { return $null }
}

# Extract the would-be-written content from a Write/Edit/MultiEdit tool_input.
function Get-MiasmaWriteContent {
    param($ToolInput)
    if (-not $ToolInput) { return '' }
    if ($ToolInput.content)    { return [string]$ToolInput.content }     # Write
    if ($ToolInput.new_string) { return [string]$ToolInput.new_string } # Edit
    if ($ToolInput.edits) {                                             # MultiEdit
        return (($ToolInput.edits | ForEach-Object { $_.new_string }) -join "`n")
    }
    return ''
}
