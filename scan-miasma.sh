#!/usr/bin/env bash
# scan-miasma.sh — Linux/macOS port of Scan-Miasma.ps1's LOCAL scan.
# Detection only, READ-ONLY (never deletes/modifies). Mirrors the cross-platform
# subset of the PowerShell local scan: injected configs, the dropper payload
# (hash + single-line eval structure), Bun temp artifacts, compromised npm deps,
# worm content signatures, git history (payload + forged commit), self-hosted
# runners, and persistence (cron/systemd/launchd). Windows-only checks
# (CVE-2026-35603 ProgramData, scheduled tasks, Run keys) are not ported.
#
# IOCs load from iocs.psd1 next to this script (single source of truth) with an
# inline fallback if absent. Exit code 1 when any INFECTED finding exists.
#
# Usage:
#   ./scan-miasma.sh                 # scan $HOME
#   ./scan-miasma.sh ~/src /opt/work # scan the given roots
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IOC="$SCRIPT_DIR/iocs.psd1"

# ----- IOC loading (parse the simple string arrays out of iocs.psd1) -----
psd1_array() { # $1=array name  $2=psd1 path  -> one value per line
  [ -f "$2" ] || return 0
  awk -v name="$1" '
    $0 ~ "^[[:space:]]*" name "[[:space:]]*=[[:space:]]*@\\(" { inb=1; next }
    inb && /^[[:space:]]*\)/ { inb=0; next }
    inb { while (match($0, /\047[^\047]*\047/)) { print substr($0, RSTART+1, RLENGTH-2); $0=substr($0, RSTART+RLENGTH) } }
  ' "$2"
}
load_array() { # $1=array-var-name $2=ioc-array-name ; shift 2 = fallback values
  local var="$1" name="$2"; shift 2
  local -a tmp=(); local line
  while IFS= read -r line; do [ -n "$line" ] && tmp+=("$line"); done < <(psd1_array "$name" "$IOC")
  if [ "${#tmp[@]}" -eq 0 ]; then tmp=("$@"); fi
  eval "$var=(\"\${tmp[@]}\")"
}

load_array CONTENT_SIGS ContentSigs \
  '.github/setup.js' 'getBunPath' 'oven-sh/bun' 'detectHardenRunner' '.sshu-setup' \
  'createCommitOnBranch' 'Runner.Worker' '169.254.169.254' 'typeof Bun'
load_array BAD_NPM BadNpm \
  '@vapi-ai/server-sdk' 'ai-sdk-ollama' 'autotel' 'awaitly' 'executable-stories' \
  'node-env-resolver' 'wrangler-deploy'
load_array PAYLOAD_SHAS PayloadShas \
  '7711CC635948D9C8F661FB91D5E226642F695AF3B82F44343F6821D8FE504668' \
  'D630397DE8B01AF0F6F5CF4463DA91B17F28195A2C50C8F3F38AD9F7873FDB8E' \
  '3A9DB5BA0C8CD4C91E91717DF6B1A141FC1E0FBC0558B5A78D7F5C23F5B2A150' \
  '633C8410EE0413CA4B090A19C30B20C03F31598C25247C484846FA34C1DF5B64' \
  'EF641E956F91D501B748085996303C96A64D67F63BFEEF0DDA175E5AA19CCA90'
BAD_EMAILS='github-actions@github.com 41898282+github-actions@users.noreply.github.com'

# ----- findings store -----
INFECTED=0; REVIEW=0
declare -a ROWS=()
is_infected_cat() { case "$1" in DROPPER|INJECT|FORGED|BADDEP|WORKFLOW|RUNNER|PAYLOAD|BUN-DROP|PROGRAMDATA) return 0;; *) return 1;; esac; }
add_finding() { # cat target detail
  local cat="$1" target="$2" detail="$3" sev
  if is_infected_cat "$cat"; then sev=INFECTED; INFECTED=$((INFECTED+1)); else sev=REVIEW; REVIEW=$((REVIEW+1)); fi
  ROWS+=("$sev|$cat|$target|$detail")
  printf '  [%-8s] %-12s %s :: %s\n' "$sev" "$cat" "$target" "$detail"
}
sec() { printf '\n== %s ==\n' "$1"; }

sha256_upper() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" 2>/dev/null | awk '{print toupper($1)}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" 2>/dev/null | awk '{print toupper($1)}'; fi
}
in_list() { local needle="$1"; shift; local x; for x in "$@"; do [ "$x" = "$needle" ] && return 0; done; return 1; }

# ----- file scan (targeted finds; node_modules always skipped) -----
scan_files() {
  local root="$1" f
  sec "File scan in $root (injected configs / payload / signatures / runners / bad deps)"

  # INJECT: AI/IDE config or manifest referencing setup.js (not under .git, <2MB)
  while IFS= read -r f; do
    grep -qsF 'setup.js' "$f" && add_finding INJECT "$f" 'references setup.js'
  done < <(find "$root" -type f \( -name settings.json -o -name tasks.json -o -name package.json -o -name Gemfile -o -name '*.mdc' \) \
             -not -path '*/node_modules/*' -not -path '*/.git/*' -size -2048k 2>/dev/null)

  # BADDEP: npm manifest referencing a compromised package
  while IFS= read -r f; do
    local pk
    for pk in "${BAD_NPM[@]}"; do
      if grep -qsF "$pk" "$f"; then add_finding BADDEP "$f" "$pk"; break; fi
    done
  done < <(find "$root" -type f \( -name package.json -o -name package-lock.json \) \
             -not -path '*/node_modules/*' -size -5120k 2>/dev/null)

  # PAYLOAD: setup.js (any size) or any 4-7MB .js — known hash or single-line eval(
  while IFS= read -r f; do
    local h first
    h="$(sha256_upper "$f")"
    if [ -n "$h" ] && in_list "$h" "${PAYLOAD_SHAS[@]}"; then
      add_finding PAYLOAD "$f" "hash match $h"
    else
      first="$(head -n1 "$f" 2>/dev/null | sed 's/^[[:space:]]*//')"
      case "$first" in eval\(*) add_finding PAYLOAD "$f" 'single-line eval()';; esac
    fi
  done < <(find "$root" -type f -name '*.js' -not -path '*/node_modules/*' \
             \( -name 'setup.js' -o \( -size +3900k -a -size -7200k \) \) 2>/dev/null)

  # SIGNATURE: worm content markers in code/json (not under .git, <8MB)
  local sigfile; sigfile="$(mktemp)"; printf '%s\n' "${CONTENT_SIGS[@]}" > "$sigfile"
  while IFS= read -r f; do
    local hit
    hit="$(grep -oFf "$sigfile" "$f" 2>/dev/null | head -n1)"
    [ -n "$hit" ] && add_finding SIGNATURE "$f" "$hit"
  done < <(find "$root" -type f \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.json' \) \
             -not -path '*/node_modules/*' -not -path '*/.git/*' -size -8192k 2>/dev/null)
  rm -f "$sigfile"

  # RUNNER: self-hosted GitHub Actions runner marker
  while IFS= read -r f; do
    add_finding RUNNER "$(dirname "$f")" 'self-hosted runner'
  done < <(find "$root" -type f -name '.runner' -not -path '*/node_modules/*' 2>/dev/null)
}

# ----- Bun temp artifacts + process -----
scan_bun() {
  sec "Bun temp artifacts + process"
  local t d
  for t in "${TMPDIR:-/tmp}" /tmp /var/tmp; do
    [ -d "$t" ] || continue
    # dirs like .b-XXXX / b_XXXX holding a bun runtime
    while IFS= read -r d; do
      if [ -e "$d/bun" ] || [ -e "$d/bun.exe" ] || [ -e "$d/b.zip" ]; then
        add_finding BUN-DROP "$d" 'bun runtime dropped'
      fi
    done < <(find "$t" -maxdepth 1 -type d \( -name '.b[-_]*' -o -name 'b[-_]*' \) 2>/dev/null)
    # loose artifacts
    while IFS= read -r d; do add_finding BUN-DROP "$d" 'temp artifact'; done < <(
      find "$t" -maxdepth 1 -type f \( -name '*.sshu-setup*' -o -name '.sshu-setup*' -o -regex '.*/p[a-z0-9]\{6,\}\.js' -o -name 'bun' -o -name 'b.zip' \) 2>/dev/null)
  done
  if command -v pgrep >/dev/null 2>&1; then
    local pid
    for pid in $(pgrep -x bun 2>/dev/null); do add_finding BUN-DROP "PID $pid" 'running: bun'; done
  fi
}

# ----- local git repos: payload in history / forged commit -----
scan_git() {
  local root="$1" g repo
  sec "Local git repos in $root (payload in history / forged commit)"
  command -v git >/dev/null 2>&1 || { echo '  git not found — skipping history checks'; return; }
  while IFS= read -r g; do
    repo="$(dirname "$g")"
    if git -C "$repo" log --all --oneline -- .github/setup.js .cursor/rules/setup.mdc .gemini/settings.json 2>/dev/null | grep -q .; then
      add_finding PAYLOAD "$repo" 'malware in git history'
    fi
    # Forged: unsigned (%G?=N) AND "skip ci" AND (impersonated bot email OR worm message)
    local n
    n="$(git -C "$repo" log --all --pretty='%G?|%ce|%s' 2>/dev/null | awk -F'|' -v emails="$BAD_EMAILS" '
      { sig=$1; email=$2; msg=$3 }
      sig=="N" && msg ~ /skip ci/ && (index(" "emails" ", " "email" ") || msg ~ /update dependencies/) { c++ }
      END { print c+0 }')"
    [ "${n:-0}" -gt 0 ] && add_finding FORGED "$repo" "$n unsigned [skip ci] commit(s)"
  done < <(find "$root" -type d -name '.git' -not -path '*/node_modules/*' 2>/dev/null)
}

# ----- persistence (cron / systemd user units / launchd) -----
scan_persistence() {
  sec "Persistence (cron / systemd / launchd)"
  local re='bun|setup\.js|\.sshu|/\.?b[-_]'
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -Eq "$re" && add_finding PERSIST 'crontab' 'user crontab references a worm artifact'
  fi
  local p
  for p in /etc/crontab /etc/cron.d "$HOME/.config/systemd/user" "$HOME/Library/LaunchAgents"; do
    [ -e "$p" ] || continue
    if grep -REq "$re" "$p" 2>/dev/null; then add_finding PERSIST "$p" 'startup entry references a worm artifact'; fi
  done
}

# ============================ run ============================
ROOTS=("$@"); [ "${#ROOTS[@]}" -eq 0 ] && ROOTS=("$HOME")
printf '###### LOCAL SCAN (bash) ###### roots: %s\n' "${ROOTS[*]}"
for r in "${ROOTS[@]}"; do [ -d "$r" ] && scan_files "$r"; done
scan_bun
for r in "${ROOTS[@]}"; do [ -d "$r" ] && scan_git "$r"; done
scan_persistence

printf '\n==================== SUMMARY ====================\n'
printf 'Findings: %d | INFECTED: %d | REVIEW: %d\n' "$((INFECTED+REVIEW))" "$INFECTED" "$REVIEW"
if [ "${#ROWS[@]}" -eq 0 ]; then echo 'No Miasma / Shai-Hulud indicators found.'; fi
[ "$INFECTED" -gt 0 ] && exit 1 || exit 0
