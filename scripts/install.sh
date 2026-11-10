#!/usr/bin/env bash
# Compensated Anarchist installer: from `git clone` to "ready to configure the model and connectors".
#
#   git clone <repo> compensatedanarchist && cd compensatedanarchist
#   ./scripts/install.sh            # then follow the printed next steps / SETUP.md
#
# What it does (safe to re-run; it never overwrites your settings and never prints secrets):
#   1. finds Python >= 3.11 and creates .venv
#   2. installs the harness (pip; or offline from a wheelhouse with --wheelhouse DIR)
#   3. creates config/.env (mode 600) from config/env.example, config/secrets/ (700), the site scope file
#      config/roe.local.yaml (600), and the evidence, vault, cases and memory folders
#   4. checks the evidence vault mount (noexec) and which local forensic tools are installed (it installs none)
#   5. runs `canarchist doctor` (and the test suite with --test)
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/install.sh [options]

  --python PATH       Python interpreter to use (default: newest python3.x >= 3.11 found)
  --forensics         also install the Python forensic tools (YARA, Volatility 3, capa, FLOSS, MemProcFS, sigma-cli)
  --core              install the harness only (no Claude / Velociraptor client libraries)
  --wheelhouse DIR    offline install: pip --no-index --find-links DIR (air-gapped networks)
  --test              install pytest and run the test suite
  --harden-vault      bind-mount evidence/vault noexec,nosuid,nodev and add it to /etc/fstab (uses sudo)
  --skip-install      do not run pip (configure folders and files only)
  -y, --yes           do not ask before using sudo
  -h, --help          this help
EOF
}

PY="" EXTRAS="connectors" WHEELHOUSE="" RUN_TESTS=0 HARDEN=0 SKIP_INSTALL=0 YES=0 FORENSICS=0
while [ $# -gt 0 ]; do
  case "$1" in
    --python) PY="$2"; shift 2 ;;
    --forensics) FORENSICS=1; shift ;;
    --core) EXTRAS=""; shift ;;
    --wheelhouse) WHEELHOUSE="$2"; shift 2 ;;
    --test) RUN_TESTS=1; shift ;;
    --harden-vault) HARDEN=1; shift ;;
    --skip-install) SKIP_INSTALL=1; shift ;;
    -y|--yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -t 1 ]; then B=$'\033[1m' G=$'\033[32m' Y=$'\033[33m' R=$'\033[31m' D=$'\033[2m' X=$'\033[0m'; else B="" G="" Y="" R="" D="" X=""; fi
step() { printf '\n%s== %s%s\n' "$B" "$*" "$X"; }
ok()   { printf '  %sok%s   %s\n' "$G" "$X" "$*"; }
warn() { printf '  %swarn%s %s\n' "$Y" "$X" "$*"; }
info() { printf '  %s%s%s\n' "$D" "$*" "$X"; }
die()  { printf '%serror:%s %s\n' "$R" "$X" "$*" >&2; exit 1; }
confirm() { [ "$YES" = 1 ] && return 0; read -r -p "  $1 [y/N] " a; [[ "$a" =~ ^[Yy] ]]; }

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
[ -f pyproject.toml ] && [ -d compensated_anarchist ] || die "run this from a Compensated Anarchist checkout (pyproject.toml not found in $REPO)"
umask 077   # everything this script creates is private unless set otherwise below

# ---------------------------------------------------------------------------------------------------------------
step "1. Python"
py_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; }
if [ -z "$PY" ]; then
  for c in python3.14 python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && py_ok "$c"; then PY="$(command -v "$c")"; break; fi
  done
fi
[ -n "$PY" ] && py_ok "$PY" || die "Python 3.11 or newer is required (install it, or pass --python /path/to/python3.x)"
"$PY" -c 'import venv, ensurepip' 2>/dev/null || die "$PY lacks venv/ensurepip (Debian/Ubuntu: apt install python3-venv)"
ok "$("$PY" -V) at $PY"

# ---------------------------------------------------------------------------------------------------------------
step "2. Virtual environment and install"
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv && ok "created .venv"
else
  ok ".venv already exists ($(.venv/bin/python -V))"
fi
PIP=(.venv/bin/python -m pip --disable-pip-version-check)
if [ -n "$WHEELHOUSE" ]; then
  [ -d "$WHEELHOUSE" ] || die "wheelhouse $WHEELHOUSE not found"
  PIP+=(--no-index --find-links "$WHEELHOUSE")
  info "offline install from $WHEELHOUSE"
fi
extras=()
[ -n "$EXTRAS" ] && extras+=("$EXTRAS")
[ "$FORENSICS" = 1 ] && extras+=("forensics")
[ "$RUN_TESTS" = 1 ] && extras+=("dev")
spec="."
[ ${#extras[@]} -gt 0 ] && spec=".[$(IFS=,; echo "${extras[*]}")]"
if [ "$SKIP_INSTALL" = 1 ]; then
  warn "skipping pip install (--skip-install)"
else
  info "pip install -e '$spec'   (this downloads packages from your configured index unless --wheelhouse)"
  "${PIP[@]}" install --quiet --upgrade pip setuptools wheel || warn "could not upgrade pip/setuptools (continuing)"
  "${PIP[@]}" install --quiet -e "$spec"
  ok "installed compensated-anarchist $spec"
fi
if [ -x .venv/bin/canarchist ]; then ok "canarchist command: .venv/bin/canarchist"; else warn "canarchist command not installed yet"; fi

# ---------------------------------------------------------------------------------------------------------------
step "3. Configuration files and folders"
if [ ! -f config/.env ]; then
  cp config/env.example config/.env
  sed -i "s/^CA_OPERATOR=.*/CA_OPERATOR=${USER:-analyst}/" config/.env
  sed -i "s/^CA_ROE=.*/CA_ROE=roe.local.yaml               # your site's scope (config\/roe.local.yaml, git-ignored)/" config/.env
  ok "created config/.env from config/env.example (operator: ${USER:-analyst})"
else
  ok "config/.env exists - left unchanged"
fi
chmod 600 config/.env

mkdir -p config/secrets && chmod 700 config/secrets && ok "config/secrets/ (700) for API configs, CA bundles, client certs"

if [ ! -f config/roe.local.yaml ]; then
  { echo "# Site ROE: copy of roe.yaml. Fill in scope.allowed_targets and scope.protected_assets (SETUP.md section 9)."
    echo "# Git-ignored. Selected with CA_ROE=roe.local.yaml in config/.env."
    cat config/roe.yaml; } > config/roe.local.yaml
  ok "created config/roe.local.yaml - set your scope before enabling Velociraptor"
else
  ok "config/roe.local.yaml exists - left unchanged"
fi
chmod 600 config/roe.local.yaml

mkdir -p evidence forensics cases memory
chmod 750 evidence forensics
mkdir -p evidence/vault && chmod 700 evidence/vault
ok "forensics/ (per-case folders: drop artifacts in forensics/<case-id>/), evidence/vault/ (700), cases/, memory/"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for f in config/.env config/secrets/x.api.yaml config/roe.local.yaml evidence/x forensics/x cases/x memory/x; do
    git check-ignore -q "$f" || warn "$f is NOT git-ignored - check .gitignore before committing anything"
  done
  ok "secrets, scope, evidence, forensics, cases and memory are git-ignored"
fi

# ---------------------------------------------------------------------------------------------------------------
step "4. Evidence vault"
VAULT="$REPO/evidence/vault"
vault_noexec() { awk -v t="$VAULT" '{mp=$5; gsub(/\\040/," ",mp); if ((t==mp || index(t, mp"/")==1) && length(mp)>=bl) {bl=length(mp); o=$6}} END {exit (o ~ /(^|,)noexec(,|$)/) ? 0 : 1}' /proc/self/mountinfo; }
if vault_noexec; then
  ok "vault is on a noexec mount"
elif [ "$HARDEN" = 1 ]; then
  if confirm "Bind-mount $VAULT noexec,nosuid,nodev and add it to /etc/fstab (sudo)?"; then
    sudo mount --bind "$VAULT" "$VAULT"
    sudo mount -o remount,bind,noexec,nosuid,nodev "$VAULT"
    grep -qsF "$VAULT $VAULT none bind" /etc/fstab || echo "$VAULT $VAULT none bind,noexec,nosuid,nodev 0 0" | sudo tee -a /etc/fstab >/dev/null
    vault_noexec && ok "vault mounted noexec (persisted in /etc/fstab)" || warn "mount did not take effect"
  fi
else
  warn "vault is not on a noexec mount. Files in it are already read-only and non-executable; for full"
  info "     protection re-run with --harden-vault, or (root):"
  info "     sudo mount --bind $VAULT $VAULT && sudo mount -o remount,bind,noexec,nosuid,nodev $VAULT"
fi

# ---------------------------------------------------------------------------------------------------------------
step "5. Local forensic tools (optional - none are installed by this script)"
have=() missing=()
for t in file strings yara vol log2timeline.py tshark zeek capa floss exiftool hayabusa chainsaw sigma fls bulk_extractor dotnet; do
  if command -v "$t" >/dev/null 2>&1 || [ -x ".venv/bin/$t" ]; then have+=("$t"); else missing+=("$t"); fi
done
[ ${#have[@]} -gt 0 ] && ok "found: ${have[*]}"
[ ${#missing[@]} -gt 0 ] && info "not found: ${missing[*]}"
info "Install only what your team needs, after clearing it with your security team (SETUP.md section 8)."
info "--forensics installs the Python ones (YARA, Volatility 3, capa, FLOSS, MemProcFS, sigma-cli) into .venv."

# ---------------------------------------------------------------------------------------------------------------
step "6. Checks"
if [ -x .venv/bin/canarchist ]; then
  if [ "$RUN_TESTS" = 1 ]; then
    .venv/bin/python -m pytest -q && ok "test suite passed" || warn "some tests failed (see above)"
  fi
  log="$(mktemp)"
  if ( set -a; . config/.env; set +a; .venv/bin/canarchist doctor --case SETUP-CHECK ) > "$log" 2>&1; then
    head -12 "$log" | sed 's/^/  /'
    ok "doctor ran (full output: .venv/bin/canarchist doctor --case SETUP-CHECK)"
  else
    tail -20 "$log" | sed 's/^/  /'
    warn "doctor failed - fix the error above (usually config/.env)"
  fi
  rm -f "$log"
else
  warn "skipping checks: canarchist is not installed"
fi

# ---------------------------------------------------------------------------------------------------------------
step "Ready for configuration"
cat <<EOF
  Next, follow SETUP.md:
    1. Model (required): edit config/.env - CA_MODEL plus that profile's URL / model / key (section 1).
    2. Connectors you have: Security Onion, Elastic, Splunk, Velociraptor, MISP, OpenCTI (sections 2-7).
       Velociraptor: run scripts/velociraptor_setup.sh on the Velociraptor server; put the key files
       in config/secrets/ (section 5).
    3. Scope: config/roe.local.yaml - allowed_targets and protected_assets (section 9).
    4. Check:     set -a; source config/.env; set +a
                  .venv/bin/canarchist doctor --case SETUP-CHECK
    5. Use it:    .venv/bin/canarchist dashboard --case IR-0001     (or: chat / run)
EOF
