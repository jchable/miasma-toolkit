<#
.SYNOPSIS
  Scan-Miasma.ps1 — unified detector for the Miasma / Shai-Hulud worm (+ CVE-2026-35603).
  READ-ONLY: detects only, never deletes/modifies.

.DESCRIPTION
  Unifies local-machine and remote-GitHub scanning into one parameterizable tool with
  structured (JSON) and Markdown report output. IOCs live in the shared iocs.psd1.

.PARAMETER Mode        Local | Remote | All   (default: All)
.PARAMETER CodeRoots   Local roots to scan (default: user profile).
.PARAMETER Owners      GitHub users/orgs to scan in Remote mode.
.PARAMETER IncludeOrgs Add the authenticated user's orgs (Remote). Default: $true.
.PARAMETER Branches    Branches checked per remote repo. Default: main,master,dev.
.PARAMETER NpmAudit    Run npm audit (lockfile-only, safe) on remote repos. Default: $true.
.PARAMETER OutJson     Optional path to write findings as JSON.
.PARAMETER OutReport   Optional path to write a Markdown report.

.EXAMPLE
  pwsh -File Scan-Miasma.ps1 -Mode Local
  pwsh -File Scan-Miasma.ps1 -Mode Remote -Owners jchable,jchable-coderise -OutReport report.md
  pwsh -File Scan-Miasma.ps1 -OutJson findings.json -OutReport report.md

.NOTES
  Remote needs `gh` authenticated; for private repos/secrets, authenticate on the target account.
  npm audit needs `npm` in PATH and runs `--package-lock-only` (no install, no scripts).
#>
[CmdletBinding()]
param(
  [ValidateSet('Local','Remote','All')][string]$Mode = 'All',
  [string[]]$CodeRoots = @("$env:USERPROFILE"),
  [string[]]$Owners    = @(),
  [bool]$IncludeOrgs   = $true,
  [string[]]$Branches  = @('main','master','dev'),
  [bool]$NpmAudit      = $true,
  [string]$OutJson,
  [string]$OutReport
)
$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'

# ============================ IOCs ============================
# Loaded from the shared iocs.psd1 (single source of truth). Inline values below
# are a fallback so the scanner stays self-contained if the data file is missing.
$IocDefaults = @{
  PayloadShas = @(
    '7711CC635948D9C8F661FB91D5E226642F695AF3B82F44343F6821D8FE504668',
    'D630397DE8B01AF0F6F5CF4463DA91B17F28195A2C50C8F3F38AD9F7873FDB8E',
    '3A9DB5BA0C8CD4C91E91717DF6B1A141FC1E0FBC0558B5A78D7F5C23F5B2A150',
    '633C8410EE0413CA4B090A19C30B20C03F31598C25247C484846FA34C1DF5B64',
    'EF641E956F91D501B748085996303C96A64D67F63BFEEF0DDA175E5AA19CCA90'
  )
  BadEmails   = @('github-actions@github.com','41898282+github-actions@users.noreply.github.com')
  ContentSigs = @('.github/setup.js','getBunPath','oven-sh/bun','detectHardenRunner','.sshu-setup','createCommitOnBranch','Runner.Worker','169.254.169.254','typeof Bun')
  BadNpm      = @('@vapi-ai/server-sdk','ai-sdk-ollama','autotel','awaitly','executable-stories','node-env-resolver','wrangler-deploy')
  ConfigFiles = @('.claude/settings.json','.gemini/settings.json','.cursor/rules/setup.mdc','.vscode/tasks.json','Gemfile')
  WfSig       = 'setup\.js|oven-sh|bun\.sh/install|node \.github|curl -fsSL https://bun|getBunPath'
  ProgramDataContentSig = 'setup\.js|\bbun\b|\.sshu|\\\.?b[-_]|\\Temp\\|fromCharCode|eval\('
  ProgramData = @(
    'C:\ProgramData\ClaudeCode\managed-settings.json',
    'C:\ProgramData\Cursor\hooks.json',
    'C:\ProgramData\openai\codex\config.toml',
    'C:\ProgramData\gemini-cli\system-defaults.json'
  )
}
$IocPath = Join-Path $PSScriptRoot 'iocs.psd1'
$IOC = $IocDefaults
if(Test-Path $IocPath){
  try { $loaded = Import-PowerShellDataFile -LiteralPath $IocPath
        foreach($k in $IocDefaults.Keys){ if(-not $loaded.ContainsKey($k)){ $loaded[$k] = $IocDefaults[$k] } }
        $IOC = $loaded }
  catch { Write-Host "WARN: failed to load $IocPath ($($_.Exception.Message)); using built-in IOCs." -ForegroundColor Yellow }
}
$PayloadShas           = $IOC.PayloadShas
$BadEmails             = $IOC.BadEmails
$ContentSigs           = $IOC.ContentSigs
$BadNpm                = $IOC.BadNpm
$ConfigFiles           = $IOC.ConfigFiles
$WfSig                 = $IOC.WfSig
$ProgramDataContentSig = $IOC.ProgramDataContentSig
$ProgramData           = $IOC.ProgramData

# ======================== Findings store ========================
$Findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$scope,[string]$target,[string]$cat,[string]$detail){
  $sev = if($cat -match '^(DROPPER|INJECT|FORGED|BADDEP|WORKFLOW|RUNNER|PAYLOAD|BUN-DROP|PROGRAMDATA)$'){'INFECTED'}else{'REVIEW'}
  $Findings.Add([pscustomobject]@{ Scope=$scope; Target=$target; Category=$cat; Severity=$sev; Detail=$detail })
  $col = switch($sev){ 'INFECTED' {'Red'} default {'Yellow'} }
  Write-Host ("  [{0,-8}] {1,-13} {2} :: {3}" -f $sev,$cat,$target,$detail) -ForegroundColor $col
}
function Sec([string]$t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

# ===================== Robust gh helpers =====================
function GhRaw($repo,$path,$ref){ $o = gh api "repos/$repo/contents/$path`?ref=$ref" -H "Accept: application/vnd.github.raw" 2>$null; if($LASTEXITCODE -eq 0){ return ($o -join "`n") } return $null }
function FileSize($repo,$path,$ref){ $s = gh api "repos/$repo/contents/$path`?ref=$ref" --jq '.size' 2>$null; if($LASTEXITCODE -eq 0 -and $s -match '^\d+$'){ return [int]$s } return $null }
function BranchExists($repo,$b){ $n = gh api "repos/$repo/branches/$b" --jq '.name' 2>$null; return ($LASTEXITCODE -eq 0 -and $n -eq $b) }
function GhJson($apiPath){ $o = gh api $apiPath 2>$null; if($LASTEXITCODE -eq 0){ try { return ($o | ConvertFrom-Json) } catch { return $null } } return $null }

# ============================================================
#  LOCAL SCAN
# ============================================================
function Invoke-LocalScan {
  $roots = $CodeRoots | Where-Object { Test-Path $_ } | Select-Object -Unique
  $temps = @($env:TEMP,$env:TMP,'C:\Windows\Temp',"$env:LOCALAPPDATA\Temp") | Where-Object { Test-Path $_ } | Select-Object -Unique
  Write-Host "`n###### LOCAL SCAN ###### roots: $($roots -join ', ')" -ForegroundColor Magenta

  Sec "CVE-2026-35603 (C:\ProgramData configs)"
  foreach($p in $ProgramData){ if(Test-Path $p){
    # Writable-by-standard-users dir is the real CVE-2026-35603 signal -> INFECTED.
    $acl = (Get-Acl (Split-Path $p)).Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
    if($acl){ Add-Finding 'Local' (Split-Path $p) 'PROGRAMDATA' 'dir writable by standard users (CVE-2026-35603)' }
    # Content matching a worm IOC -> INFECTED; a generic command/hook only -> REVIEW (avoid FP).
    if(Select-String -LiteralPath $p -Pattern $ProgramDataContentSig -Quiet){ Add-Finding 'Local' $p 'PROGRAMDATA' 'config references a worm IOC -> inspect' }
    elseif(Select-String -LiteralPath $p -Pattern '"(command|hook|hooks)"|(^|\s)(node|bun|powershell|pwsh|cmd|sh|bash)\s|cmd\s*/c' -Quiet){ Add-Finding 'Local' $p 'PROGRAMDATA-CFG' 'config defines commands -> inspect manually' }
  }}

  Sec "File scan (injected configs / payload / signatures / runners / bad deps)"
  # Single recursive pass per root; each file is dispatched to every applicable rule
  # (replaces the former 5 separate -Recurse walks). Filters per rule are preserved.
  foreach($r in $roots){ Get-ChildItem $r -Recurse -File -EA SilentlyContinue | ForEach-Object {
    $full = $_.FullName
    if($full -match '\\node_modules\\'){ return }   # excluded by every file rule
    $nm = $_.Name; $len = $_.Length; $ext = $_.Extension.ToLowerInvariant()
    $inGit = $full -match '\\\.git\\'

    # RUNNER: self-hosted GitHub Actions runner marker.
    if($nm -eq '.runner'){ Add-Finding 'Local' $_.DirectoryName 'RUNNER' 'self-hosted runner'; return }

    # INJECT: AI/IDE config or manifest referencing setup.js.
    if(-not $inGit -and $len -lt 2MB -and ($nm -in 'settings.json','tasks.json','package.json','Gemfile' -or $ext -eq '.mdc')){
      if(Select-String -LiteralPath $full -SimpleMatch 'setup.js' -Quiet){ Add-Finding 'Local' $full 'INJECT' 'references setup.js' } }

    # BADDEP: npm manifest referencing a compromised package.
    if($len -lt 5MB -and ($nm -eq 'package.json' -or $nm -eq 'package-lock.json')){
      foreach($pk in $BadNpm){ if(Select-String -LiteralPath $full -SimpleMatch $pk -Quiet){ Add-Finding 'Local' $full 'BADDEP' $pk; break } } }

    # PAYLOAD: setup.js or any 4-7 MB .js (known hash / single-line eval).
    if($ext -eq '.js' -and ($nm -eq 'setup.js' -or ($len -ge 4MB -and $len -le 7MB))){
      $h = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash
      if($PayloadShas -contains $h){ Add-Finding 'Local' $full 'PAYLOAD' "hash match $h" }
      else { $f0 = Get-Content -LiteralPath $full -TotalCount 1; if($f0 -and $f0.TrimStart().StartsWith('eval(')){ Add-Finding 'Local' $full 'PAYLOAD' "single-line eval() $($len)o" } } }

    # SIGNATURE: worm content markers in code/json.
    if(-not $inGit -and $len -lt 8MB -and ($ext -in '.js','.mjs','.cjs','.ts','.json')){
      foreach($s in $ContentSigs){ if(Select-String -LiteralPath $full -SimpleMatch $s -Quiet){ Add-Finding 'Local' $full 'SIGNATURE' $s; break } } }
  } }

  Sec "Bun temp artifacts + process"
  foreach($t in $temps){
    Get-ChildItem $t -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '^\.?b[-_]' } |
      ForEach-Object { if((Test-Path "$($_.FullName)\bun.exe") -or (Test-Path "$($_.FullName)\bun") -or (Test-Path "$($_.FullName)\b.zip")){ Add-Finding 'Local' $_.FullName 'BUN-DROP' 'bun runtime dropped' } }
    Get-ChildItem $t -File -EA SilentlyContinue | Where-Object { $_.Name -match '\.sshu-setup|^p[a-z0-9]{6,}\.js$|^bun\.exe$|^b\.zip$' } |
      ForEach-Object { Add-Finding 'Local' $_.FullName 'BUN-DROP' 'temp artifact' } }
  Get-Process bun -EA SilentlyContinue | ForEach-Object { Add-Finding 'Local' "PID $($_.Id)" 'BUN-DROP' "running: $($_.Path)" }

  Sec "Local git repos (payload in history / forged commit)"
  foreach($r in $roots){ Get-ChildItem $r -Recurse -Directory -Filter '.git' -EA SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
    ForEach-Object { $repo = Split-Path $_.FullName -Parent
      # Malware file still reachable in any commit -> PAYLOAD.
      if(git -C $repo log --all --oneline -- .github/setup.js .cursor/rules/setup.mdc .gemini/settings.json 2>$null){ Add-Finding 'Local' $repo 'PAYLOAD' 'malware in git history' }
      # Forged commit: unsigned (%G? = N) AND [skip ci] AND (impersonated bot email OR worm message).
      $forged = git -C $repo log --all --pretty='%G?|%ce|%s' 2>$null | Where-Object {
        $x = $_ -split '\|',3
        ($x[0] -eq 'N') -and ($x[2] -match 'skip ci') -and ( ($BadEmails -contains $x[1]) -or ($x[2] -match 'update dependencies') )
      }
      if($forged){ Add-Finding 'Local' $repo 'FORGED' "$(@($forged).Count) unsigned [skip ci] commit(s)" }
    } }

  Sec "Persistence (scheduled tasks / Run keys)"
  Get-ScheduledTask -EA SilentlyContinue | Where-Object { (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ') -match 'bun|setup\.js|\\\.?b[-_]|Local\\Temp' } | ForEach-Object { Add-Finding 'Local' $_.TaskName 'PERSIST' 'scheduled task' }
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object { $k = Get-ItemProperty $_ -EA SilentlyContinue; if($k){ $k.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value -match 'bun|setup\.js|\\\.?b[-_]' } | ForEach-Object { Add-Finding 'Local' $_.Name 'PERSIST' "Run key: $($_.Value)" } } }
}

# ============================================================
#  REMOTE SCAN
# ============================================================
function Invoke-RemoteScan {
  gh auth status 2>$null | Out-Null
  if($LASTEXITCODE -ne 0){ Write-Host "gh not authenticated -> skip Remote (run 'gh auth login')." -ForegroundColor Red; return }
  $me = gh api user --jq .login 2>$null
  Write-Host "`n###### REMOTE SCAN ###### gh user: $me" -ForegroundColor Magenta
  $audit = $NpmAudit -and (Get-Command npm -EA SilentlyContinue)
  $owners = @($Owners)
  if($IncludeOrgs){ $owners += @(gh api user/orgs --paginate --jq '.[].login' 2>$null) }
  if(-not $owners){ $owners = @($me) }
  $owners = $owners | Where-Object { $_ } | Select-Object -Unique
  Write-Host "Owners: $($owners -join ', ') | Branches: $($Branches -join ', ')" -ForegroundColor Cyan

  $repos = @()
  foreach($o in $owners){ $j = gh repo list $o --limit 1000 --json nameWithOwner,visibility,isFork 2>$null | ConvertFrom-Json; if($j){ $repos += $j } }
  $repos = $repos | Sort-Object nameWithOwner -Unique
  Write-Host "Repos: $($repos.Count)`n" -ForegroundColor Cyan

  $i = 0
  foreach($r in $repos){
    $i++; $name = $r.nameWithOwner
    Write-Progress -Activity "Remote scan" -Status "$i/$($repos.Count) $name" -PercentComplete (($i/$repos.Count)*100)
    $cache = @{}
    foreach($b in $Branches){
      if(-not (BranchExists $name $b)){ continue }
      if($null -ne (FileSize $name '.github/setup.js' $b)){ Add-Finding 'Remote' $name 'DROPPER' "[$b] .github/setup.js" }
      foreach($cf in $ConfigFiles){ $c = GhRaw $name $cf $b; if($c -and ($c -match 'setup\.js')){ Add-Finding 'Remote' $name 'INJECT' "[$b] $cf" } }
      $pkg = GhRaw $name 'package.json' $b
      if($pkg){ if($pkg -match 'setup\.js'){ Add-Finding 'Remote' $name 'INJECT' "[$b] package.json script" }
        foreach($pk in $BadNpm){ if($pkg -match [regex]::Escape($pk)){ Add-Finding 'Remote' $name 'BADDEP' "[$b] $pk" } } }
      # Forged commit: unsigned + [skip ci] AND (impersonated bot email OR worm message).
      # The extra email/message condition avoids flagging legitimate unsigned [skip ci] commits.
      $bad = @((GhJson "repos/$name/commits?per_page=50&sha=$b") | Where-Object {
        $_.commit.verification.verified -eq $false -and $_.commit.message -match 'skip ci' -and (
          ($BadEmails -contains $_.commit.author.email) -or ($BadEmails -contains $_.commit.committer.email) -or
          ($_.commit.message -match 'update dependencies') ) })
      if($bad.Count){ Add-Finding 'Remote' $name 'FORGED' "[$b] $($bad.Count) forged [skip ci] commit(s), ex $($bad[0].sha.Substring(0,7))" }
      foreach($w in (GhJson "repos/$name/contents/.github/workflows?ref=$b")){ if($w.name -match '\.ya?ml$'){ $wc = GhRaw $name ".github/workflows/$($w.name)" $b; if($wc -and ($wc -match $WfSig)){ Add-Finding 'Remote' $name 'WORKFLOW' "[$b] $($w.name)" } } }
      if($audit -and $pkg){ $lock = GhRaw $name 'package-lock.json' $b
        if($lock){ $key = "$($lock.Length):$($lock.Substring(0,[Math]::Min(64,$lock.Length)))"
          if(-not $cache.ContainsKey($key)){
            $tmp = Join-Path $env:TEMP ("npmaudit-"+[guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $tmp | Out-Null
            # WriteAllText -> UTF-8 without BOM, portable across PowerShell 5.1 and 7 (npm-safe JSON).
            [System.IO.File]::WriteAllText("$tmp\package.json", $pkg); [System.IO.File]::WriteAllText("$tmp\package-lock.json", $lock)
            Push-Location $tmp; $au = (npm audit --package-lock-only --json 2>$null | Out-String); Pop-Location; Remove-Item $tmp -Recurse -Force
            $res=$null; try{ $v=($au|ConvertFrom-Json).metadata.vulnerabilities; if($v -and (($v.critical+$v.high) -gt 0)){ $res="$($v.critical) crit / $($v.high) high" } }catch{}
            $cache[$key]=$res }
          if($cache[$key]){ Add-Finding 'Remote' $name 'NPM-AUDIT' "[$b] $($cache[$key])" } } }
    }
    foreach($rr in (GhJson "repos/$name/actions/runners").runners){ Add-Finding 'Remote' $name 'RUNNER' "self-hosted $($rr.name) ($($rr.os)/$($rr.status))" }
    $sec = (GhJson "repos/$name/actions/secrets").secrets; if($sec){ Add-Finding 'Remote' $name 'SECRETS' "$($sec.Count) Actions secret(s) (rotate)" }
  }
  Write-Progress -Activity "Remote scan" -Completed
  foreach($org in ($owners | Where-Object { gh api "orgs/$_" --silent 2>$null; $LASTEXITCODE -eq 0 })){
    foreach($rr in (GhJson "orgs/$org/actions/runners").runners){ Add-Finding 'Remote' "org:$org" 'RUNNER' "org self-hosted $($rr.name)" }
    $os = (GhJson "orgs/$org/actions/secrets").secrets; if($os){ Add-Finding 'Remote' "org:$org" 'SECRETS' "$($os.Count) org secret(s) (rotate)" }
  }
}

# ============================ RUN ============================
if($Mode -in 'Local','All'){ Invoke-LocalScan }
if($Mode -in 'Remote','All'){ Invoke-RemoteScan }

# ========================== OUTPUT ==========================
$infected = @($Findings | Where-Object { $_.Severity -eq 'INFECTED' })
$review   = @($Findings | Where-Object { $_.Severity -eq 'REVIEW' })
Write-Host "`n==================== SUMMARY ====================" -ForegroundColor Cyan
Write-Host ("Findings: {0} | INFECTED: {1} | REVIEW: {2}" -f $Findings.Count,$infected.Count,$review.Count) -ForegroundColor $(if($infected.Count){'Red'}elseif($review.Count){'Yellow'}else{'Green'})
if($Findings.Count){ $Findings | Sort-Object Severity,Scope,Target | Format-Table -AutoSize -Wrap }
else { Write-Host "No Miasma / Shai-Hulud indicators found." -ForegroundColor Green }

if($OutJson){ $Findings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $OutJson -Encoding utf8; Write-Host "JSON -> $OutJson" -ForegroundColor Cyan }
if($OutReport){
  $md = New-Object System.Collections.Generic.List[string]
  $md.Add("# Miasma / Shai-Hulud scan report")
  $md.Add(""); $md.Add("- Mode: ``$Mode``"); $md.Add("- Findings: **$($Findings.Count)** (INFECTED: **$($infected.Count)**, REVIEW: $($review.Count))")
  $md.Add(""); $md.Add("| Severity | Scope | Category | Target | Detail |"); $md.Add("|---|---|---|---|---|")
  foreach($f in ($Findings | Sort-Object Severity,Scope,Target)){ $md.Add("| $($f.Severity) | $($f.Scope) | $($f.Category) | $($f.Target) | $($f.Detail) |") }
  if(-not $Findings.Count){ $md.Add("`n_No indicators found._") }
  $md -join "`n" | Set-Content -LiteralPath $OutReport -Encoding utf8; Write-Host "Markdown -> $OutReport" -ForegroundColor Cyan
}
exit ([int]($infected.Count -gt 0))
