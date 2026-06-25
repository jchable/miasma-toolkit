<#
.SYNOPSIS
  Expand-MiasmaPayload.ps1 — static (non-executing) deobfuscator for the Miasma /
  Shai-Hulud ".github/setup.js" dropper. Peels the documented layers and extracts
  the embedded C2 / IOC strings WITHOUT ever running the payload.

.DESCRIPTION
  The dropper is a single-line, multi-layer blob (see content/incident-report):

    Layer 0 : eval( <array of ~1.37M char codes> )          -> char-code wave
    Layer 1 : JS with identifiers Caesar-shifted (shift 8 our wave; ROT-4/9 others)
    Layer 2 : AES-128-GCM decryptor with key/IV/tag/ciphertext IN CLEAR + 2 blobs
                 _b (~907 o) bootstrapper Bun
                 _p (~685 Ko) infostealer (re-obfuscated)

  Because the AES parameters are embedded in clear, the blobs are decryptable
  statically. This tool: reads the file READ-ONLY, decodes char codes -> reverses
  the Caesar shift (auto-detected, overridable) -> extracts every AES-128-GCM
  call (key/iv/tag/ciphertext) and decrypts it with .NET AesGcm -> writes the
  recovered layers to -OutDir and scans them for indicators.

  BEST-EFFORT: layer structure varies by wave. The char-code + Caesar + AES-GCM
  ("our wave") is fully supported; the Caesar self-decoder packer wave is detected
  but only partially handled. Intermediate artifacts are written at every step so
  an analyst can inspect even when a later layer fails. Use -SelfTest to verify
  the decode/decrypt engine on a synthetic 3-layer sample.

  Requires PowerShell 7+ (uses System.Security.Cryptography.AesGcm).

.PARAMETER Path     The setup.js (or any candidate dropper) to deobfuscate. READ-ONLY.
.PARAMETER OutDir   Where to write recovered layers (default: <Path>.deob next to it).
.PARAMETER Shift    Force the Caesar shift (0-25) instead of auto-detecting.
.PARAMETER SelfTest Run an in-memory round-trip test of the engine and exit.

.EXAMPLE
  pwsh -File Expand-MiasmaPayload.ps1 -Path .github/setup.js
  pwsh -File Expand-MiasmaPayload.ps1 -Path setup.js -OutDir out -Shift 8
  pwsh -File Expand-MiasmaPayload.ps1 -SelfTest

.NOTES
  Read-only on the input. Never executes the payload (no eval, no node, no bun).
  Loads IOC content signatures from iocs.psd1 when present (single source of truth).
#>
[CmdletBinding()]
param(
  [string]$Path,
  [string]$OutDir,
  [ValidateRange(0,25)][int]$Shift = -1,
  [switch]$SelfTest
)
$ErrorActionPreference = 'Stop'    # this is an analysis tool; surface failures

# ============================ helpers ============================
function HexToBytes([string]$h){
  $h = $h -replace '[^0-9a-fA-F]',''
  $n = $h.Length / 2
  $b = [byte[]]::new($n)
  for($i=0;$i -lt $n;$i++){ $b[$i] = [Convert]::ToByte($h.Substring($i*2,2),16) }
  return ,$b
}
function BytesToHex([byte[]]$b){ ([System.BitConverter]::ToString($b)).Replace('-','').ToLower() }

# Construct an AesGcm handle across .NET versions (.NET 8 made the 1-arg ctor obsolete;
# it now wants an explicit tag size in bytes).
function New-AesGcm([byte[]]$key){
  try   { return [System.Security.Cryptography.AesGcm]::new($key, 16) }
  catch { return [System.Security.Cryptography.AesGcm]::new($key) }
}

# Layer 0: decode the char-code wave. Pulls the longest comma-separated integer run
# and maps each code to a char. Returns $null if no such run exists (other waves).
function ConvertFrom-CharCodes([string]$text){
  $m = [regex]::Matches($text, '\d+(?:\s*,\s*\d+){200,}')
  if($m.Count -eq 0){ return $null }
  $run = ($m | Sort-Object { $_.Value.Length } -Descending | Select-Object -First 1).Value
  $codes = $run -split '\s*,\s*'
  $sb = [System.Text.StringBuilder]::new($codes.Count)
  foreach($c in $codes){ [void]$sb.Append([char][int]$c) }
  return $sb.ToString()
}

# Reverse a Caesar alpha shift (subtract $shift mod 26); non-letters untouched.
function Invoke-CaesarShift([string]$text,[int]$shift){
  $arr = $text.ToCharArray()
  for($i=0;$i -lt $arr.Length;$i++){
    $ch = $arr[$i]
    if($ch -ge 'a' -and $ch -le 'z'){ $arr[$i] = [char]((([int]$ch - 97 - $shift) % 26 + 26) % 26 + 97) }
    elseif($ch -ge 'A' -and $ch -le 'Z'){ $arr[$i] = [char]((([int]$ch - 65 - $shift) % 26 + 26) % 26 + 65) }
  }
  return -join $arr
}

# Score how "JavaScript-like" a string is (used to auto-pick the Caesar shift).
function Get-JsScore([string]$text){
  $kw = 'const','await','import','function','return','crypto','Buffer','require',
        'createDecipheriv','globalThis','async','setAuthTag'
  $s = 0
  foreach($k in $kw){ $s += ([regex]::Matches($text,[regex]::Escape($k))).Count }
  return $s
}
function Get-CaesarShift([string]$text){
  # Probe on a representative slice for speed; full string only matters for output.
  $sample = if($text.Length -gt 200000){ $text.Substring(0,200000) } else { $text }
  $best = 0; $bestScore = -1
  for($s=0;$s -lt 26;$s++){
    $score = Get-JsScore (Invoke-CaesarShift $sample $s)
    if($score -gt $bestScore){ $bestScore = $score; $best = $s }
  }
  return [pscustomobject]@{ Shift=$best; Score=$bestScore }
}

# Layer 2: find every AES-128-GCM call (key=32hex, iv=24hex, tag=32hex, ciphertext)
# and decrypt it. Returns an array of recovered plaintext byte[] blobs.
function Expand-AesGcm([string]$js){
  $rx = '["'']([0-9a-fA-F]{32})["'']\s*,\s*["'']([0-9a-fA-F]{24})["'']\s*,\s*["'']([0-9a-fA-F]{32})["'']\s*,\s*["'']([0-9a-fA-F]{2,})["'']'
  $out = @()
  foreach($m in [regex]::Matches($js,$rx)){
    $key = HexToBytes $m.Groups[1].Value
    $iv  = HexToBytes $m.Groups[2].Value
    $tag = HexToBytes $m.Groups[3].Value
    $ct  = HexToBytes $m.Groups[4].Value
    $pt  = [byte[]]::new($ct.Length)
    $aes = New-AesGcm $key
    try   { $aes.Decrypt($iv,$ct,$tag,$pt); $ok=$true }
    catch { $ok=$false; Write-Host "  AES-GCM decrypt failed (key $($m.Groups[1].Value.Substring(0,8))...): $($_.Exception.Message)" -ForegroundColor Yellow }
    finally { $aes.Dispose() }
    if($ok){ $out += [pscustomobject]@{ KeyHex=$m.Groups[1].Value; IvHex=$m.Groups[2].Value; Plain=$pt } }
  }
  return ,$out
}

# --- Caesar self-decoder / "p,a,c,k,e,d" packer wave (Dean Edwards style) ---
# Outer form: eval(function(p,a,c,k,e,d){...}('PAYLOAD',RADIX,COUNT,'w1|w2|...'.split('|'),0,{}))
# Static unpack: rebuild each base-RADIX token and substitute its dictionary word.

# Minimal JS string unescape for the captured payload/dictionary (\\ and \' only;
# enough to recover token text — we are not executing anything).
function JsUnescape([string]$s){ return ($s -replace '\\([\\''])','$1') }

# The packer's index->token encoder `e(c)` (base RADIX; digits 0-9a-z, then A-Z via c+29).
function Get-PackerToken([int]$c,[int]$a){
  $prefix = if($c -lt $a){ '' } else { Get-PackerToken ([math]::Floor($c / $a)) $a }
  $r = $c % $a
  # JS toString(36): 0-9 -> '0'-'9', 10-35 -> 'a'-'z'; >35 -> fromCharCode(r+29) ('A'..).
  # (.NET [Convert]::ToString supports only bases 2/8/10/16, so map digits by hand.)
  $ch = if($r -gt 35){ [char]($r + 29) } elseif($r -lt 10){ [char](48 + $r) } else { [char](87 + $r) }
  return $prefix + [string]$ch
}

# Unpack a p,a,c,k,e,d payload. Returns the unpacked source, or $null if not this wave.
function Expand-Packer([string]$text){
  if($text -notmatch 'function\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,\s*d\s*\)'){ return $null }
  $rx = [regex]'(?s)\}\s*\(\s*''(?<p>(?:\\.|[^''\\])*)''\s*,\s*(?<a>\d+)\s*,\s*(?<c>\d+)\s*,\s*''(?<k>(?:\\.|[^''\\])*)''\s*\.\s*split\(\s*''\|''\s*\)'
  $m = $rx.Match($text)
  if(-not $m.Success){ return $null }
  $p = JsUnescape $m.Groups['p'].Value
  $a = [int]$m.Groups['a'].Value
  $c = [int]$m.Groups['c'].Value
  $k = (JsUnescape $m.Groups['k'].Value) -split '\|'
  # Substitute high index -> low, exactly as the packer's `while(c--)` loop does.
  for($i = $c - 1; $i -ge 0; $i--){
    if($i -lt $k.Count -and $k[$i] -ne ''){
      $tok  = Get-PackerToken $i $a
      $word = $k[$i].Replace('$','$$')          # $ is a substitution token in .NET replace
      $p = [regex]::Replace($p, '\b' + [regex]::Escape($tok) + '\b', $word)
    }
  }
  return $p
}

# Scan recovered plaintext for indicators. Reuses iocs.psd1 ContentSigs when present;
# adds network patterns (URLs, IPs, dead-drop accounts) the static layers don't carry.
function Find-PayloadIocs([string]$text){
  $sigs = @('.github/setup.js','getBunPath','oven-sh/bun','detectHardenRunner','.sshu-setup',
            'createCommitOnBranch','Runner.Worker','169.254.169.254','typeof Bun','createDecipheriv','aes-128-gcm')
  $iocPath = Join-Path $PSScriptRoot 'iocs.psd1'
  if(Test-Path $iocPath){ try { $d = Import-PowerShellDataFile -LiteralPath $iocPath; if($d.ContentSigs){ $sigs = @($d.ContentSigs + $sigs | Select-Object -Unique) } } catch {} }
  $hits = [ordered]@{}
  foreach($s in $sigs){ $n = ([regex]::Matches($text,[regex]::Escape($s))).Count; if($n){ $hits["literal:$s"] = $n } }
  $patterns = @{
    'url'            = 'https?://[^\s"''<>\\]{6,}'
    'ipv4'           = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    'github-account' = '\b(?:windy629|liuende501|HerGomUli)\b'
    'github-pat'     = 'github_pat_[A-Za-z0-9_]+'
  }
  foreach($p in $patterns.GetEnumerator()){
    # Group identical matches and count them. (Do NOT use String.Split($v) — in
    # PowerShell that splits on each CHARACTER of $v, not the whole substring.)
    foreach($g in ([regex]::Matches($text,$p.Value) | Group-Object Value)){
      $hits["$($p.Key):$($g.Name)"] = $g.Count
    }
  }
  return $hits
}

# ============================ self-test ============================
# Build a synthetic 3-layer sample (char codes -> Caesar shift 8 -> AES-128-GCM)
# and verify the pipeline recovers the inner blob. Proves the engine is sound when
# no real sample is on hand.
function Invoke-SelfTest {
  Write-Host "Self-test: building synthetic char-code -> Caesar(8) -> AES-128-GCM sample" -ForegroundColor Cyan
  $secret = 'globalThis.getBunPath=()=>"https://github.com/oven-sh/bun/releases"; var c2="169.254.169.254";'
  $key = [byte[]](1..16); $iv = [byte[]](1..12)
  $ptBytes = [System.Text.Encoding]::UTF8.GetBytes($secret)
  $ct = [byte[]]::new($ptBytes.Length); $tag = [byte[]]::new(16)
  $aes = New-AesGcm $key
  try { $aes.Encrypt($iv,$ptBytes,$ct,$tag) } finally { $aes.Dispose() }
  $layer2 = 'const _c=await import("node:crypto");const _b=_d("{0}","{1}","{2}","{3}");' -f (BytesToHex $key),(BytesToHex $iv),(BytesToHex $tag),(BytesToHex $ct)
  $layer1 = Invoke-CaesarShift $layer2 -8                       # encode: shift forward by 8
  # Pad to exceed the 200-token char-code run threshold, then encode all of it.
  $payload = $layer1 + ('0123456789' * 30)
  $codes = ($payload.ToCharArray() | ForEach-Object { [int]$_ }) -join ','
  $layer0 = "eval(String.fromCharCode($codes))"

  $dec0 = ConvertFrom-CharCodes $layer0
  if($dec0 -ne $payload){ Write-Host "FAIL: char-code decode mismatch" -ForegroundColor Red; return 1 }
  $sh = Get-CaesarShift $dec0
  if($sh.Shift -ne 8){ Write-Host "FAIL: Caesar shift detected $($sh.Shift), expected 8" -ForegroundColor Red; return 1 }
  $dec1 = Invoke-CaesarShift $dec0 $sh.Shift
  $blobs = Expand-AesGcm $dec1
  if($blobs.Count -ne 1){ Write-Host "FAIL: expected 1 blob, got $($blobs.Count)" -ForegroundColor Red; return 1 }
  $recovered = [System.Text.Encoding]::UTF8.GetString($blobs[0].Plain)
  if($recovered -ne $secret){ Write-Host "FAIL: recovered blob mismatch" -ForegroundColor Red; return 1 }
  $iocs = Find-PayloadIocs $recovered
  Write-Host "PASS: char codes -> Caesar(8) -> AES-128-GCM round-trip OK; recovered $($iocs.Count) indicator(s)." -ForegroundColor Green

  # Packer wave: build a p,a,c,k,e,d sample and verify static unpacking.
  Write-Host "Self-test: building synthetic p,a,c,k,e,d packer sample" -ForegroundColor Cyan
  $expected = 'function foo(){}'
  $packed = "eval(function(p,a,c,k,e,d){return p}('0 1(){}',10,2,'function|foo'.split('|'),0,{}))"
  $un = Expand-Packer $packed
  if($un -ne $expected){ Write-Host "FAIL: packer unpack got '$un', expected '$expected'" -ForegroundColor Red; return 1 }
  Write-Host "PASS: p,a,c,k,e,d packer unpack round-trip OK." -ForegroundColor Green
  return 0
}

# ============================ run ============================
if($SelfTest){ exit (Invoke-SelfTest) }

if(-not $Path){ Write-Host "Provide -Path <setup.js> (or -SelfTest)." -ForegroundColor Red; exit 2 }
if(-not (Test-Path -LiteralPath $Path)){ Write-Host "Not found: $Path" -ForegroundColor Red; exit 2 }
$full = (Resolve-Path -LiteralPath $Path).Path
if(-not $OutDir){ $OutDir = "$full.deob" }
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Write-Host "Reading (read-only): $full" -ForegroundColor Cyan
$raw = [System.IO.File]::ReadAllText($full)
Write-Host ("  {0:N0} bytes, first chars: {1}" -f $raw.Length, ($raw.Substring(0,[Math]::Min(24,$raw.Length)).Trim())) -ForegroundColor DarkGray

# Pre-layer: p,a,c,k,e,d packer wave. If present, unpack first; the result then
# flows through the same char-code -> Caesar -> AES pipeline below.
$unpacked = Expand-Packer $raw
if($unpacked){
  $pp = Join-Path $OutDir '0-unpacked.js'
  [System.IO.File]::WriteAllText($pp,$unpacked); Write-Host "Packer wave (p,a,c,k,e,d) unpacked -> $pp" -ForegroundColor Green
  $raw = $unpacked
}

# Layer 0
$layer0 = ConvertFrom-CharCodes $raw
if($null -eq $layer0){
  Write-Host "No char-code array found (Caesar self-decoder wave?) — treating raw text as layer 0." -ForegroundColor Yellow
  $layer0 = $raw
} else {
  $p0 = Join-Path $OutDir '1-charcodes.js'
  [System.IO.File]::WriteAllText($p0,$layer0); Write-Host "Layer 0 (char codes decoded) -> $p0" -ForegroundColor Green
}

# Layer 1 (Caesar)
if($layer0 -match 'createDecipheriv|aes-128-gcm'){
  Write-Host "Layer 0 already readable JS (no Caesar) — skipping shift." -ForegroundColor DarkGray
  $layer1 = $layer0; $usedShift = 0
} else {
  if($Shift -ge 0){ $usedShift = $Shift; Write-Host "Using forced Caesar shift $usedShift." -ForegroundColor Cyan }
  else { $det = Get-CaesarShift $layer0; $usedShift = $det.Shift; Write-Host "Auto-detected Caesar shift $usedShift (JS score $($det.Score))." -ForegroundColor Cyan }
  $layer1 = Invoke-CaesarShift $layer0 $usedShift
}
$p1 = Join-Path $OutDir '2-caesar.js'
[System.IO.File]::WriteAllText($p1,$layer1); Write-Host "Layer 1 (Caesar reversed, shift $usedShift) -> $p1" -ForegroundColor Green

# Layer 2 (AES-128-GCM)
$blobs = Expand-AesGcm $layer1
if($blobs.Count -eq 0){
  Write-Host "No AES-128-GCM (key,iv,tag,ciphertext) tuples found. Inspect $p1 manually." -ForegroundColor Yellow
} else {
  Write-Host "Recovered $($blobs.Count) AES-128-GCM blob(s):" -ForegroundColor Green
  $i = 0
  foreach($b in $blobs){
    $i++
    $name = if($i -eq 1){ 'blob_b' } elseif($i -eq 2){ 'blob_p' } else { "blob_$i" }
    $bp = Join-Path $OutDir "$name.js"
    [System.IO.File]::WriteAllBytes($bp,$b.Plain)
    Write-Host ("  #{0} {1}: {2:N0} bytes (key {3}...) -> {4}" -f $i,$name,$b.Plain.Length,$b.KeyHex.Substring(0,8),$bp) -ForegroundColor Green
  }
}

# IOC scan of everything we recovered (de-Caesared layer + decrypted blobs)
$scanText = $layer1
foreach($b in $blobs){ $scanText += "`n" + [System.Text.Encoding]::UTF8.GetString($b.Plain) }
$iocs = Find-PayloadIocs $scanText
Write-Host "`n==================== INDICATORS ====================" -ForegroundColor Cyan
if($iocs.Count -eq 0){ Write-Host "No indicators extracted." -ForegroundColor Yellow }
else {
  foreach($k in $iocs.Keys){ Write-Host ("  [{0,3}x] {1}" -f $iocs[$k],$k) }
  $report = Join-Path $OutDir 'iocs.txt'
  ($iocs.GetEnumerator() | ForEach-Object { "{0}`t{1}" -f $_.Value,$_.Key }) -join "`n" | Set-Content -LiteralPath $report -Encoding utf8
  Write-Host "Indicators -> $report" -ForegroundColor Cyan
}
exit 0
