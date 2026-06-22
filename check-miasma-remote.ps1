<#
  Miasma / Shai-Hulud — scanner des repos DISTANTS GitHub (READ-ONLY)  [v2 — bug DROPPER corrige]
  Branches : main, master, dev (si presentes). Verifs robustes via $LASTEXITCODE (gh deverse le
  corps d'erreur 404 sur stdout, donc on NE se fie PAS a la truthiness de la sortie).
#>
$ErrorActionPreference = 'SilentlyContinue'

# ===================== CONFIG =====================
$Owners      = @('jchable','jchable-coderise')
$IncludeOrgs = $true
$RunNpmAudit = $true
$Branches    = @('main','master','dev')
$BadNpm      = @('@vapi-ai/server-sdk','ai-sdk-ollama','autotel','awaitly','executable-stories','node-env-resolver','wrangler-deploy')
$ConfigFiles = @('.claude/settings.json','.gemini/settings.json','.cursor/rules/setup.mdc','.vscode/tasks.json','Gemfile')
$WfSig       = 'setup\.js|oven-sh|bun\.sh/install|node \.github|curl -fsSL https://bun|getBunPath'

# ===================== Helpers robustes =====================
function GhOK($apiArgs){ $o = gh api @apiArgs 2>$null; if($LASTEXITCODE -eq 0){ return $o } else { return $null } }
function BranchExists($repo,$b){ $n = gh api "repos/$repo/branches/$b" --jq '.name' 2>$null; return ($LASTEXITCODE -eq 0 -and $n -eq $b) }
function FileSize($repo,$path,$ref){ $s = gh api "repos/$repo/contents/$path`?ref=$ref" --jq '.size' 2>$null; if($LASTEXITCODE -eq 0 -and $s -match '^\d+$'){ return [int]$s } else { return $null } }
function GhRaw($repo,$path,$ref){ $o = gh api "repos/$repo/contents/$path`?ref=$ref" -H "Accept: application/vnd.github.raw" 2>$null; if($LASTEXITCODE -eq 0){ return ($o -join "`n") } else { return $null } }
function GhJson($apiPath){ $o = gh api $apiPath 2>$null; if($LASTEXITCODE -eq 0){ try{ return ($o | ConvertFrom-Json) }catch{ return $null } } else { return $null } }

# ===================== Pre-checks =====================
gh auth status 2>$null | Out-Null
if($LASTEXITCODE -ne 0){ Write-Host "ERREUR: gh non authentifie. 'gh auth login'." -ForegroundColor Red; return }
Write-Host "gh authentifie : $(gh api user --jq .login 2>$null)" -ForegroundColor Cyan
if($RunNpmAudit -and -not (Get-Command npm -EA SilentlyContinue)){ Write-Host "npm absent -> audit desactive." -ForegroundColor Yellow; $RunNpmAudit=$false }
$orgList = @(); if($IncludeOrgs){ $orgList = @(gh api user/orgs --paginate --jq '.[].login' 2>$null); $Owners += $orgList }
$Owners = $Owners | Where-Object { $_ } | Select-Object -Unique
Write-Host "Owners : $($Owners -join ', ') | Branches : $($Branches -join ', ')`n" -ForegroundColor Cyan

# ===================== Enumeration =====================
$repos = @()
foreach($o in $Owners){ $j = gh repo list $o --limit 1000 --json nameWithOwner,visibility,isFork 2>$null | ConvertFrom-Json; if($j){ $repos += $j } }
$repos = $repos | Sort-Object nameWithOwner -Unique
Write-Host "Repos a analyser : $($repos.Count)`n" -ForegroundColor Cyan

$results = New-Object System.Collections.Generic.List[object]
$i = 0
foreach($r in $repos){
  $i++; $name = $r.nameWithOwner
  Write-Progress -Activity "Scan repos distants" -Status "$i/$($repos.Count) : $name" -PercentComplete (($i/$repos.Count)*100)
  $f = New-Object System.Collections.Generic.List[string]; $auditCache = @{}

  foreach($b in $Branches){
    if(-not (BranchExists $name $b)){ continue }

    $sz = FileSize $name '.github/setup.js' $b
    if($null -ne $sz){ $f.Add("[$b] DROPPER setup.js ($sz o)") }

    foreach($cf in $ConfigFiles){ $c = GhRaw $name $cf $b; if($c -and ($c -match 'setup\.js')){ $f.Add("[$b] INJECT $cf") } }

    $pkgTxt = GhRaw $name 'package.json' $b
    if($pkgTxt){
      if($pkgTxt -match 'setup\.js'){ $f.Add("[$b] INJECT package.json") }
      foreach($pk in $BadNpm){ if($pkgTxt -match [regex]::Escape($pk)){ $f.Add("[$b] BAD-DEP $pk") } }
    }

    $bad = (GhJson "repos/$name/commits?per_page=50&sha=$b") | Where-Object { $_.commit.message -match 'skip ci' -and $_.commit.verification.verified -eq $false }
    if($bad){ $f.Add("[$b] FORGED-COMMIT x$($bad.Count) (ex $($bad[0].sha.Substring(0,7)))") }

    $wf = GhJson "repos/$name/contents/.github/workflows?ref=$b"
    foreach($w in $wf){ if($w.name -match '\.ya?ml$'){ $wc = GhRaw $name ".github/workflows/$($w.name)" $b; if($wc -and ($wc -match $WfSig)){ $f.Add("[$b] WORKFLOW-INJECT $($w.name)") } } }

    if($RunNpmAudit -and $pkgTxt){
      $lockTxt = GhRaw $name 'package-lock.json' $b
      if($lockTxt){
        $key = "$($lockTxt.Length):$($lockTxt.Substring(0,[Math]::Min(64,$lockTxt.Length)))"
        if(-not $auditCache.ContainsKey($key)){
          $tmp = Join-Path $env:TEMP ("npmaudit-" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $tmp | Out-Null
          $pkgTxt | Set-Content "$tmp\package.json"; $lockTxt | Set-Content "$tmp\package-lock.json"
          Push-Location $tmp; $au = (npm audit --package-lock-only --json 2>$null | Out-String); Pop-Location; Remove-Item $tmp -Recurse -Force
          $res=$null; try{ $v=($au|ConvertFrom-Json).metadata.vulnerabilities; if($v -and (($v.critical+$v.high) -gt 0)){ $res="$($v.critical) crit / $($v.high) high" } }catch{}
          $auditCache[$key]=$res
        }
        if($auditCache[$key]){ $f.Add("[$b] npm audit: $($auditCache[$key])") }
      }
    }
  }

  # Actions niveau repo
  $runners = (GhJson "repos/$name/actions/runners").runners
  foreach($rr in $runners){ $f.Add("SELF-RUNNER $($rr.name) ($($rr.os)/$($rr.status))") }
  $secrets = (GhJson "repos/$name/actions/secrets").secrets
  if($secrets){ $f.Add("ACTIONS-SECRETS x$($secrets.Count) (a tourner)") }

  if($f.Count -gt 0){
    $sev = if(($f -join ' ') -match 'DROPPER|INJECT|FORGED|BAD-DEP|SELF-RUNNER|WORKFLOW-INJECT'){'INFECTE'}else{'A-VERIFIER'}
    $results.Add([pscustomobject]@{ Repo=$name; Visib=$r.visibility; Niveau=$sev; Findings=($f -join ' | ') })
    Write-Host ("[{0,-10}] {1} :: {2}" -f $sev,$name,($f -join ' | ')) -ForegroundColor $(if($sev -eq 'INFECTE'){'Red'}else{'Yellow'})
  } else { Write-Host ("[ok        ] {0}" -f $name) -ForegroundColor DarkGray }
}
Write-Progress -Activity "Scan repos distants" -Completed

# Actions niveau ORG
if($orgList.Count){
  Write-Host "`n== Actions niveau ORG ==" -ForegroundColor Cyan
  foreach($org in ($orgList | Select-Object -Unique)){
    foreach($rr in (GhJson "orgs/$org/actions/runners").runners){ Write-Host "  [!] ORG-SELF-RUNNER $org/$($rr.name) ($($rr.os)/$($rr.status))" -ForegroundColor Red }
    $os = (GhJson "orgs/$org/actions/secrets").secrets; if($os){ Write-Host "  [i] $org : $($os.Count) secret(s) org (a tourner)" -ForegroundColor Yellow }
  }
}

# Synthese
Write-Host "`n==================== SYNTHESE ====================" -ForegroundColor Cyan
$inf = ($results | Where-Object { $_.Niveau -eq 'INFECTE' }).Count; $ver = ($results | Where-Object { $_.Niveau -eq 'A-VERIFIER' }).Count
Write-Host "Repos: $($repos.Count) | INFECTE: $inf | A-VERIFIER: $ver" -ForegroundColor $(if($inf){'Red'}elseif($ver){'Yellow'}else{'Green'})
if($results.Count){ $results | Sort-Object Niveau,Repo | Format-Table -AutoSize -Wrap } else { Write-Host "Aucun repo distant suspect." -ForegroundColor Green }
