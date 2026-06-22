<#
  Miasma / Shai-Hulud worm + CVE-2026-35603 — machine + repos checker (READ-ONLY)
  Refs: dev.to/icflorescu/the-bot-that-never-was | safedep.io/miasma-worm... | cymulate CVE-2026-35603
  Usage:  pwsh -ExecutionPolicy Bypass -File check-miasma.ps1
#>
$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'

# ===================== CONFIG : racines a scanner (ADAPTE) =====================
$CodeRoots = @("$env:USERPROFILE", 'E:\', 'D:\') | Where-Object { Test-Path $_ } | Select-Object -Unique
$TempRoots = @($env:TEMP, $env:TMP, 'C:\Windows\Temp', "$env:LOCALAPPDATA\Temp") | Where-Object { Test-Path $_ } | Select-Object -Unique

# ===================== IOCs (multi-variantes) =====================
$PayloadShas = @(
  '7711CC635948D9C8F661FB91D5E226642F695AF3B82F44343F6821D8FE504668', # ta variante
  'D630397DE8B01AF0F6F5CF4463DA91B17F28195A2C50C8F3F38AD9F7873FDB8E', # icflorescu/taxepfa
  '3A9DB5BA0C8CD4C91E91717DF6B1A141FC1E0FBC0558B5A78D7F5C23F5B2A150', # Azure/durabletask
  '633C8410EE0413CA4B090A19C30B20C03F31598C25247C484846FA34C1DF5B64', # payload _p
  'EF641E956F91D501B748085996303C96A64D67F63BFEEF0DDA175E5AA19CCA90'  # binding.gyp
)
$BadEmails   = @('github-actions@github.com','41898282+github-actions@users.noreply.github.com','owner@example.com')
$ContentSigs = @('.github/setup.js','getBunPath','oven-sh/bun','detectHardenRunner','.sshu-setup','createCommitOnBranch','Runner.Worker','169.254.169.254','typeof Bun')
$BadNpm      = @('@vapi-ai/server-sdk','ai-sdk-ollama','autotel','awaitly','executable-stories','node-env-resolver','wrangler-deploy')
$ProgramData = @(
  'C:\ProgramData\ClaudeCode\managed-settings.json',
  'C:\ProgramData\Cursor\hooks.json',
  'C:\ProgramData\openai\codex\config.toml',
  'C:\ProgramData\gemini-cli\system-defaults.json'
)

$global:HITS = 0
function Hit($c,$d){ $global:HITS++; Write-Host ("  [!] {0,-15} {1}" -f $c,$d) -ForegroundColor Red }
function Note($d){ Write-Host "  [i] $d" -ForegroundColor Yellow }
function Sec($t){ Write-Host "`n== $t ==" -ForegroundColor Cyan }

# 0) CVE-2026-35603 : configs systeme dans C:\ProgramData
Sec "0. CVE-2026-35603 : configs C:\ProgramData (Claude/Cursor/Codex/Gemini)"
foreach($p in $ProgramData){ if(Test-Path $p){
  if(Select-String -LiteralPath $p -SimpleMatch 'command','hook','node ','bun ','setup.js','powershell','cmd /c','.exe' -Quiet){ Hit 'PROGRAMDATA-CFG' "$p (contient des commandes -> INSPECTER)" }
  else { Note "present (a verifier ACL/contenu): $p" }
  $acl = (Get-Acl (Split-Path $p)).Access | Where-Object { $_.IdentityReference -match 'Users|Everyone|Authenticated' -and $_.FileSystemRights -match 'Write|Modify|FullControl' }
  if($acl){ Hit 'PROGRAMDATA-ACL' "$(Split-Path $p) inscriptible par utilisateurs standards (vuln CVE-2026-35603)" }
}}
$cc = (Get-Command claude -EA SilentlyContinue); if($cc){ Note "Claude Code installe -> verifie version >= 2.0.76" }

# 1) Fichiers injectes referencant setup.js
Sec "1. Fichiers injectes (.claude/.gemini/.cursor/.vscode/package.json/Gemfile)"
foreach($r in $CodeRoots){
  Get-ChildItem $r -Recurse -File -Include 'settings.json','tasks.json','*.mdc','package.json','Gemfile' -EA SilentlyContinue |
    Where-Object { $_.Length -lt 2MB -and $_.FullName -notmatch '\\node_modules\\|\\\.git\\' } |
    ForEach-Object { if(Select-String -LiteralPath $_.FullName -SimpleMatch 'setup.js' -Quiet){ Hit 'INJECT-CONFIG' $_.FullName } }
}

# 2) Payload : setup.js / .js 4-7 Mo (hash connus + structure eval)
Sec "2. Payload setup.js / .js 4-7 Mo (hash + 1ere ligne eval)"
foreach($r in $CodeRoots){
  Get-ChildItem $r -Recurse -File -Include '*.js' -EA SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' -and ($_.Name -eq 'setup.js' -or ($_.Length -ge 4MB -and $_.Length -le 7MB)) } |
    ForEach-Object {
      $h = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
      if($PayloadShas -contains $h){ Hit 'PAYLOAD(hash)' $_.FullName }
      else { $f = Get-Content -LiteralPath $_.FullName -TotalCount 1; if($f -and $f.TrimStart().StartsWith('eval(')){ Hit 'PAYLOAD(eval)' "$($_.FullName) [$($_.Length)o]" } }
    }
}

# 3) Signatures de contenu du ver
Sec "3. Signatures de contenu (getBunPath, detectHardenRunner, oven-sh, IMDS, typeof Bun...)"
foreach($r in $CodeRoots){
  Get-ChildItem $r -Recurse -File -Include '*.js','*.mjs','*.cjs','*.ts','*.json' -EA SilentlyContinue |
    Where-Object { $_.Length -lt 8MB -and $_.FullName -notmatch '\\node_modules\\|\\\.git\\' } |
    ForEach-Object { $p=$_.FullName; foreach($s in $ContentSigs){ if(Select-String -LiteralPath $p -SimpleMatch $s -Quiet){ Hit 'SIGNATURE' "$p :: $s"; break } } }
}

# 4) Artefacts Bun en temp + process
Sec "4. Artefacts Bun temp (b-*, .b_*, bun.exe, b.zip, .sshu-setup, p<rand>.js) + process"
foreach($t in $TempRoots){
  Get-ChildItem $t -Directory -EA SilentlyContinue | Where-Object { $_.Name -match '^\.?b[-_]' } |
    ForEach-Object { if((Test-Path "$($_.FullName)\bun.exe") -or (Test-Path "$($_.FullName)\bun") -or (Test-Path "$($_.FullName)\b.zip")){ Hit 'BUN-DROP' $_.FullName } }
  Get-ChildItem $t -File -EA SilentlyContinue | Where-Object { $_.Name -match '\.sshu-setup|^p[a-z0-9]{6,}\.js$|^bun\.exe$|^b\.zip$' } |
    ForEach-Object { Hit 'TEMP-ARTIFACT' $_.FullName }
}
Get-Process bun -EA SilentlyContinue | ForEach-Object { Hit 'BUN-PROCESS' "PID $($_.Id) $($_.Path)" }

# 5) Historique git de TOUS les depots locaux
Sec "5. Depots git : payload en historique OU commit [skip ci] non signe"
foreach($r in $CodeRoots){
  Get-ChildItem $r -Recurse -Directory -Filter '.git' -EA SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' } |
    ForEach-Object {
      $repo = Split-Path $_.FullName -Parent
      if(git -C $repo log --all --oneline -- .github/setup.js .cursor/rules/setup.mdc .gemini/settings.json 2>$null){ Hit 'REPO-PAYLOAD' $repo }
      $bad = git -C $repo log --all --pretty='%G?|%ce|%s' 2>$null | Where-Object {
        $x = $_ -split '\|',3
        ($x[0] -eq 'N') -and ($x[2] -match 'skip ci') -and ( ($BadEmails -contains $x[1]) -or ($x[2] -match 'update dependencies') )
      }
      if($bad){ Hit 'FORGED-COMMIT' "$repo ($($bad.Count) commit(s))" }
    }
}

# 6) Persistance
Sec "6. Persistance (taches / Run / Demarrage referencant bun/setup.js/b-)"
Get-ScheduledTask -EA SilentlyContinue | Where-Object {
  $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' '
  $a -match 'bun|setup\.js|\\\.?b[-_]|Local\\Temp' } | ForEach-Object { Hit 'SCHED-TASK' $_.TaskName }
'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | ForEach-Object {
  $k = Get-ItemProperty $_ -EA SilentlyContinue
  if($k){ $k.PSObject.Properties | Where-Object { $_.Value -is [string] -and $_.Value -match 'bun|setup\.js|\\\.?b[-_]' } | ForEach-Object { Hit 'RUN-KEY' "$($_.Name) = $($_.Value)" } } }
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -EA SilentlyContinue |
  Where-Object { $_.Name -match 'bun|setup' } | ForEach-Object { Hit 'STARTUP' $_.FullName }

# 7) Runners GitHub Actions auto-heberges
Sec "7. Runners self-hosted suspects (.runner)"
foreach($r in $CodeRoots){ Get-ChildItem $r -Recurse -File -Filter '.runner' -EA SilentlyContinue | ForEach-Object { Hit 'SELF-RUNNER' $_.DirectoryName } }

# 8) Dependances npm compromises (registry arm Miasma)
Sec "8. Dependances npm compromises (vapi-ai, ai-sdk-ollama, jagreehal/*...)"
foreach($r in $CodeRoots){
  Get-ChildItem $r -Recurse -File -Include 'package.json','package-lock.json','pnpm-lock.yaml','yarn.lock' -EA SilentlyContinue |
    Where-Object { $_.Length -lt 5MB -and $_.FullName -notmatch '\\node_modules\\' } |
    ForEach-Object { $p=$_.FullName; foreach($pk in $BadNpm){ if(Select-String -LiteralPath $p -SimpleMatch $pk -Quiet){ Hit 'NPM-BAD-PKG' "$p :: $pk"; break } } }
}

# ===================== RESULTAT =====================
$col = if($global:HITS -gt 0){'Red'}else{'Green'}
Write-Host ("`n==================== RESULTAT : {0} IOC(s) ====================" -f $global:HITS) -ForegroundColor $col
if($global:HITS -eq 0){ Write-Host "Aucun indicateur Miasma / CVE-2026-35603 dans les chemins scannes." -ForegroundColor Green }
else { Write-Host "Revois chaque [!]. Nettoyage + rotation des secrets requis." -ForegroundColor Yellow }
