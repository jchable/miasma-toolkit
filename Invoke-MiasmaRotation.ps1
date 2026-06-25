<#
.SYNOPSIS
  Invoke-MiasmaRotation.ps1 — guided secret-rotation checklist after a Miasma /
  Shai-Hulud infection. READ-ONLY: it detects which credentials are reachable from
  this machine and prints the exact revoke/rotate commands — it NEVER revokes
  anything itself (rotation is destructive and must stay a human decision).

.DESCRIPTION
  The Miasma infostealer harvests every developer secret it can reach (GitHub/npm
  tokens, cloud credentials, SSH/GPG keys, Vault/K8s tokens, browser passwords).
  After eradication you MUST rotate everything the machine could touch. This script
  turns incident-report §7 (steps 7–8) into an actionable, prioritized checklist:
  it probes (read-only) which credential stores exist here, marks them DETECTED,
  and emits ready-to-run revoke commands per category. Run the commands yourself.

  Read-only by design (toolkit convention): no token is revoked, no file changed.

.PARAMETER OutReport  Optional path to write the checklist as Markdown (with checkboxes).
.PARAMETER NoProbe    Skip local detection; emit the full checklist for every category.

.EXAMPLE
  pwsh -File Invoke-MiasmaRotation.ps1
  pwsh -File Invoke-MiasmaRotation.ps1 -OutReport rotation.md
#>
[CmdletBinding()]
param(
  [string]$OutReport,
  [switch]$NoProbe
)
$ErrorActionPreference = 'SilentlyContinue'; $ProgressPreference = 'SilentlyContinue'

function Has([string]$p){ return (Test-Path -LiteralPath $p) }
function FileHas([string]$p,[string]$needle){ if(Has $p){ return [bool](Select-String -LiteralPath $p -SimpleMatch $needle -Quiet) } return $false }

# Each item: priority (1 highest), name, a read-only detector, and the commands to run.
$home2 = $HOME
$checks = @(
  @{ P=1; Name='GitHub — PAT / fine-grained tokens';
     Detect={ if($env:GITHUB_TOKEN -or $env:GH_TOKEN -or (Has "$home2/.config/gh/hosts.yml")){ return $true }; gh auth status 2>$null | Out-Null; return ($LASTEXITCODE -eq 0) };
     Why='The worm spreads via the GitHub API and forges commits — rotate FIRST.';
     Cmds=@('Revoke at https://github.com/settings/tokens (classic) and /settings/personal-access-tokens (fine-grained)',
            'gh auth status            # see which account/scopes are active',
            'gh auth refresh            # re-auth with a fresh, minimal-scope token',
            'Review OAuth apps / GitHub Apps / deploy keys: https://github.com/settings/applications') }
  @{ P=1; Name='GitHub Actions secrets (repo + org)';
     Detect={ gh auth status 2>$null | Out-Null; return ($LASTEXITCODE -eq 0) };
     Why='Actions secrets and self-hosted runners are abused for propagation.';
     Cmds=@('gh secret list -R <owner>/<repo>          # inventory',
            'gh secret delete <NAME> -R <owner>/<repo>  # then re-create rotated values',
            'gh api orgs/<org>/actions/secrets --jq ".secrets[].name"  # org-level',
            'Remove unexpected self-hosted runners: repo/org Settings -> Actions -> Runners') }
  @{ P=1; Name='npm tokens';
     Detect={ (FileHas "$home2/.npmrc" '_authToken') -or $env:NPM_TOKEN };
     Why='npm publish tokens let the worm poison the registry arm.';
     Cmds=@('npm token list',
            'npm token revoke <token-id>',
            'Then: npm login   # mint a fresh token (and prefer granular/automation tokens)') }
  @{ P=1; Name='AWS credentials';
     Detect={ (Has "$home2/.aws/credentials") -or $env:AWS_ACCESS_KEY_ID };
     Why='Stolen keys + IMDS abuse give cloud access.';
     Cmds=@('aws iam list-access-keys',
            'aws iam update-access-key --access-key-id <AKIA...> --status Inactive   # then delete',
            'aws iam create-access-key   # issue a replacement',
            'Rotate anything in Secrets Manager / SSM the key could read') }
  @{ P=2; Name='Google Cloud credentials';
     Detect={ (Has "$home2/.config/gcloud") -or (Has "$home2/.config/gcloud/application_default_credentials.json") };
     Why='ADC + service-account keys + Secret Manager exposure.';
     Cmds=@('gcloud auth revoke --all',
            'gcloud auth application-default revoke',
            'gcloud iam service-accounts keys list --iam-account <sa>   # delete/rotate keys') }
  @{ P=2; Name='Azure credentials';
     Detect={ (Has "$home2/.azure") -or $env:AZURE_CLIENT_SECRET };
     Why='Managed identity / Key Vault exposure.';
     Cmds=@('az logout',
            'az ad app credential reset --id <appId>   # rotate client secrets',
            'Rotate Key Vault secrets the principal could read') }
  @{ P=2; Name='SSH private keys';
     Detect={ Has "$home2/.ssh" };
     Why='Private keys grant git/server access.';
     Cmds=@('ls ~/.ssh/id_*   # identify keys',
            'ssh-keygen -t ed25519   # regenerate, then replace public keys on GitHub/servers',
            'Remove unknown keys at https://github.com/settings/keys') }
  @{ P=2; Name='GPG signing keys';
     Detect={ (gpg --list-secret-keys 2>$null) -ne $null };
     Why='Signing keys can forge trusted commits.';
     Cmds=@('gpg --list-secret-keys --keyid-format=long',
            'Revoke compromised keys (gpg --gen-revoke) and remove at https://github.com/settings/keys') }
  @{ P=2; Name='HashiCorp Vault token';
     Detect={ Has "$home2/.vault-token" };
     Why='A live Vault token unlocks everything Vault brokers.';
     Cmds=@('vault token revoke -self',
            'Rotate any static secrets the token could read') }
  @{ P=3; Name='Kubernetes credentials';
     Detect={ Has "$home2/.kube/config" };
     Why='Service-account tokens / kubeconfig grant cluster access.';
     Cmds=@('kubectl config view --minify   # identify context/SA',
            'Rotate ServiceAccount tokens / client certs for the affected cluster') }
  @{ P=3; Name='NuGet API keys';
     Detect={ (FileHas "$env:APPDATA/NuGet/NuGet.Config" 'apikey') -or (FileHas "$home2/.nuget/NuGet/NuGet.Config" 'apikey') };
     Why='Package-feed publish keys.';
     Cmds=@('Revoke/rotate keys in your NuGet/Azure Artifacts feed settings',
            'nuget setapikey <new-key> -Source <feed>') }
  @{ P=3; Name='Browser-stored passwords & sessions';
     Detect={ $true };
     Why='The stealer scrapes saved passwords and session cookies.';
     Cmds=@('Change passwords for high-value accounts (email, cloud, code hosts)',
            'Sign out everywhere / invalidate sessions where supported',
            'Re-enable / re-enroll MFA where it may have been bypassed') }
)

$detected = @()
foreach($c in $checks){
  $isDet = if($NoProbe){ $true } else { try { [bool](& $c.Detect) } catch { $false } }
  $c.Detected = $isDet
  if($isDet){ $detected += $c }
}

# Console
Write-Host "`n=========== MIASMA SECRET-ROTATION CHECKLIST (read-only) ===========" -ForegroundColor Cyan
if($NoProbe){ Write-Host "Mode: full checklist (-NoProbe; detection skipped)" -ForegroundColor DarkGray }
else { Write-Host ("Detected {0} of {1} credential store(s) reachable from this machine." -f $detected.Count,$checks.Count) -ForegroundColor Yellow }
Write-Host "Nothing is revoked automatically — run the commands below yourself.`n" -ForegroundColor DarkGray
foreach($c in ($checks | Sort-Object P, Name)){
  $tag = if($c.Detected){ if($NoProbe){'[ ]'} else {'[DETECTED]'} } else { '[not found]' }
  $col = if($c.Detected){ if($c.P -eq 1){'Red'}else{'Yellow'} } else { 'DarkGray' }
  Write-Host ("P{0} {1,-11} {2}" -f $c.P,$tag,$c.Name) -ForegroundColor $col
  if($c.Detected){
    Write-Host "      why: $($c.Why)" -ForegroundColor DarkGray
    foreach($cmd in $c.Cmds){ Write-Host "      > $cmd" -ForegroundColor Gray }
  }
}

# Markdown report
if($OutReport){
  $md = New-Object System.Collections.Generic.List[string]
  $md.Add("# Miasma secret-rotation checklist"); $md.Add("")
  $md.Add("> Read-only helper — nothing is revoked automatically. Treat every secret reachable")
  $md.Add("> from this machine as compromised and rotate it. Priority **P1** first.")
  $md.Add("")
  foreach($c in ($checks | Sort-Object P, Name)){
    $box = if($c.Detected -and -not $NoProbe){ '🔴 ' } else { '' }
    $state = if($NoProbe){ '' } elseif($c.Detected){ ' — **detected on this machine**' } else { ' — _not found here_' }
    $md.Add("- [ ] $box**P$($c.P) · $($c.Name)**$state")
    $md.Add("  - _$($c.Why)_")
    foreach($cmd in $c.Cmds){ $md.Add("  - ``$cmd``") }
  }
  $md.Add(""); $md.Add("After rotation: re-scan all repos with ``Scan-Miasma.ps1`` and audit the GitHub *Security log* for the malicious push.")
  $md -join "`n" | Set-Content -LiteralPath $OutReport -Encoding utf8
  Write-Host "`nMarkdown -> $OutReport" -ForegroundColor Cyan
}
