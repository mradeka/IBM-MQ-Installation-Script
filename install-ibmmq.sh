#!/usr/bin/env bash
#===============================================================================
# install-ibmmq.sh
#
# IBM MQ 9.4.x / 10.0.x (LTS) – installation and hardening script
#
# Compatible with IBM MQ 9.4.x (Continuous Delivery) and IBM MQ 10.0.x
# (Long Term Support, GA since June 2026). Package formats, mqlicense.sh,
# crtmqm/runmqsc syntax and the RPM/DEB naming convention (MQSeriesXYZ /
# ibmmq-xyz) are unchanged between these versions, so this single
# script installs both code levels unchanged and automatically – which
# version gets installed is decided solely by the supplied --media.
#
# Supported platforms:
#   - Red Hat Enterprise Linux 8/9/10 (and compatibles: Rocky, Alma) -> RPM
#     (RHEL 8: IBM MQ 9.4.x only; RHEL 9/10: IBM MQ 9.4.x and 10.0.x)
#     (RDQM/multi-instance with HA kernel module: RHEL x86-64 only)
#   - SUSE Linux Enterprise Server 15                              -> RPM
#   - Ubuntu 20.04/22.04/24.04 (x86-64)                            -> DEB
#   - Raspberry Pi 4/5 with 64-bit OS (Raspberry Pi OS / Ubuntu)   -> DEB (ARM64)
#   - Raspberry Pi with 32-bit OS                                  -> DEB (ARM32, "as-is")
#
# Note on TLS: since IBM MQ 9.2.0, TLS 1.3 is already the default for newly
# created queue managers (qm.ini AllowTLSV13). The default CipherSpec of this
# script (ANY_TLS12_OR_HIGHER) remains valid for 9.4.x and 10.0.x; if needed,
# check 'runmqakm -cipher -list' for additional, newer CipherSpecs of the
# installed GSKit version.
#
# Features:
#   - Platform and architecture detection
#   - Interactive prompting for MQ parameters (QM name, port, packages ...)
#   - Prompting for and enabling the standard security features
#   - Applying IBM best practices (CONNAUTH, CHLAUTH, dedicated
#     app user, minimal permissions, optional TLS)
#
# IMPORTANT: The MQ installation media (tar.gz from Passport Advantage or
#            the Developer Edition) must be available locally. This script
#            does NOT download the media (license/entitlement reasons).
#
# Usage:
#   sudo ./install-ibmmq.sh --media /path/to/MQServer-10.0.0.x-Linux.tar.gz   (or 9.4.0.x)
#   sudo ./install-ibmmq.sh --media /path/to/extracted/MQServer-directory
#   sudo ./install-ibmmq.sh --media <path> --non-interactive   (uses defaults/ENV)
#
# License: GNU General Public License v2 (see LICENSE.md). No warranty.
#===============================================================================

set -Eeuo pipefail

#-------------------------------------------------------------------------------
# 0) Global defaults  (can be overridden via ENV or --non-interactive)
#-------------------------------------------------------------------------------
MQ_QMGR_NAME="${MQ_QMGR_NAME:-QM1}"          # Name of the (first) queue manager
MQ_LISTENER_PORT="${MQ_LISTENER_PORT:-1414}" # TCP listener port of the (first) QM
MQ_DLQ="${MQ_DLQ:-SYSTEM.DEAD.LETTER.QUEUE}" # Dead letter queue
MQ_APP_CHANNEL="${MQ_APP_CHANNEL:-APP.SVRCONN}" # Dedicated app channel (default per QM)
MQ_EXPLORER_CHANNEL="${MQ_EXPLORER_CHANNEL:-EXPLORER.SVRCONN}" # Dedicated channel ONLY for MQ Explorer/admin tools
MQ_APP_USER="${MQ_APP_USER:-mqapp}"          # Non-privileged app user (shared)
MQ_APP_GROUP="${MQ_APP_GROUP:-mqappusers}"   # OS group that permissions are granted to
                                              # (instead of per user - IBM best practice:
                                              # simply add new app users/channels to this group
                                              # instead of running setmqaut again)
MQ_APP_QUEUE="${MQ_APP_QUEUE:-APP.QUEUE.1}"  # Sample application queue (per QM)
MQ_INSTALL_PATH="${MQ_INSTALL_PATH:-/opt/mqm}"

# OS tuning for IBM MQ (kernel parameters, ulimits) - IBM-documented
# MINIMUM values (see "Configuring the operating system on Linux" in the
# IBM MQ docs); only raised, never lowered. empty = ask interactively.
OS_TUNE_MQ="${OS_TUNE_MQ:-}"
MQ_NOFILE_LIMIT="${MQ_NOFILE_LIMIT:-10240}"
MQ_NPROC_LIMIT="${MQ_NPROC_LIMIT:-4096}"

# Logging options (per QM)
MQ_LOG_TYPE="${MQ_LOG_TYPE:-circular}"       # circular | linear
MQ_LOG_PRIMARY="${MQ_LOG_PRIMARY:-4096}"     # Primary log size in 4K blocks (1st log)
MQ_LOG_SECONDARY="${MQ_LOG_SECONDARY:-1024}" # Secondary log size in 4K blocks (2nd log, linear only)

# Further common queue manager parameters (shared by all QMs)
MQ_MAXMSGL="${MQ_MAXMSGL:-4194304}"          # Max. message length in bytes (MAXMSGL), default 4 MB
MQ_MAXCHL="${MQ_MAXCHL:-100}"                # Max. number of defined channels (MAXCHL)
MQ_MAXACTCHL="${MQ_MAXACTCHL:-256}"          # Max. number of concurrently active channels (MAXACTCHL)
MQ_DESCR="${MQ_DESCR:-}"                     # Free-text description of the QM (DESCR), optional

# Multiple queue managers (1..x):
#   MQ_QMGRS="NAME[:PORT[:CHANNEL]]"
#   - Ports can be given as a range PORT_START-PORT_END
#   - Channel is still optional and defaults to MQ_APP_CHANNEL
#
#   e.g. MQ_QMGRS="QM1:1414,QM2:1415-1420:APP.SVRCONN,QM3:1421-1425"
#   -> QM1 port 1414, QM2 ports 1415-1420, QM3 ports 1421-1425
#
# If MQ_QMGRS is set, it takes precedence over MQ_QMGR_NAME/PORT/CHANNEL.
MQ_QMGRS="${MQ_QMGRS:-}"
declare -a QMGR_NAMES=() QMGR_PORTS=() QMGR_CHANNELS=()

# Security switches (yes/no)
SEC_CONNAUTH="${SEC_CONNAUTH:-yes}"          # Connection authentication (user/password)
SEC_CHLAUTH="${SEC_CHLAUTH:-yes}"            # Channel authentication records
SEC_BLOCK_PRIV="${SEC_BLOCK_PRIV:-yes}"      # Block privileged users on channels
SEC_TLS="${SEC_TLS:-no}"                     # TLS key repository + self-signed cert
SEC_AMS="${SEC_AMS:-no}"                     # Install Advanced Message Security
INST_WEB="${INST_WEB:-no}"                   # Install MQ Web Console
ENABLE_AUTOSTART="${ENABLE_AUTOSTART:-yes}"  # Set up systemd autostart

# Convenience aliases (tail-/mqsc-/status-/... per QM, system-wide via profile.d)
ENABLE_ALIASES="${ENABLE_ALIASES:-yes}"

# Mode selection for --non-interactive (otherwise via main menu): install|addqm|upgrade|feature|backup
MQ_MODE="${MQ_MODE:-install}"

# Upgrade options (mode "upgrade")
UPGRADE_BACKUP="${UPGRADE_BACKUP:-yes}"      # Back up /var/mqm before the upgrade
UPGRADE_BACKUP_DIR="${UPGRADE_BACKUP_DIR:-/var/mqm-backup-$(date +%Y%m%d-%H%M%S)}"

# Add-on feature options (mode "feature": add to an existing installation)
FEATURE_MQTT="${FEATURE_MQTT:-}"              # yes/no, empty = ask interactively
FEATURE_AMS="${FEATURE_AMS:-}"                # yes/no, empty = ask interactively
FEATURE_WEB="${FEATURE_WEB:-}"                # reserved, currently unused: the Web Console can only be chosen at new installation
MQTT_QM="${MQTT_QM:-}"                        # Target QM for MQTT/Telemetry, empty = ask
MQTT_SET_DEFXMITQ="${MQTT_SET_DEFXMITQ:-no}"  # Set SYSTEM.MQTT.TRANSMIT.QUEUE as DEFXMITQ

# Backup options (mode "backup")
BACKUP_DIR="${BACKUP_DIR:-/var/mqm-backups}"  # Target directory for backups
BACKUP_STOP_QM="${BACKUP_STOP_QM:-yes}"       # Stop QM for a consistent data backup
BACKUP_QMS="${BACKUP_QMS:-}"                  # empty/"all" = all, otherwise comma-separated names

# Restore options (mode "restore")
RESTORE_SRC_DIR="${RESTORE_SRC_DIR:-$BACKUP_DIR}"  # Source directory with *-config-*.mqsc / *-data-*.tar.gz
RESTORE_MODE="${RESTORE_MODE:-config}"             # config = MQSC configuration only | full = restore data/log archive
RESTORE_QM="${RESTORE_QM:-}"                       # Target QM/backup base name, empty = choose interactively
RESTORE_TS="${RESTORE_TS:-}"                       # Timestamp of the desired backup, empty = newest or ask

# Mode "install": behavior when IBM MQ packages are already found on the host
# (empty = ask interactively; yes = install/downgrade anyway, with --allow-downgrades
# or --oldpackage; no = abort and point to addqm/upgrade/feature)
FORCE_REINSTALL="${FORCE_REINSTALL:-}"

# Mode "uninstall": complete removal of an existing installation
UNINSTALL_CONFIRM="${UNINSTALL_CONFIRM:-}"        # empty = ask interactively; yes/no for automation
UNINSTALL_BACKUP_FIRST="${UNINSTALL_BACKUP_FIRST:-yes}"  # offer a backup before removal
UNINSTALL_REMOVE_USER="${UNINSTALL_REMOVE_USER:-no}"     # additionally remove mqm user/group + /var/mqm

# TLS defaults
TLS_CIPHER="${TLS_CIPHER:-ANY_TLS12_OR_HIGHER}"
TLS_CERT_DN="${TLS_CERT_DN:-CN=${MQ_QMGR_NAME},O=Example,C=DE}"

# Web Console defaults
WEB_ADMIN_USER="${WEB_ADMIN_USER:-mqadmin}"  # Web admin (only in mqweb, no OS account needed)
WEB_ADMIN_PASS="${WEB_ADMIN_PASS:-}"         # empty = ask interactively / generate
WEB_RO_USER="${WEB_RO_USER:-}"               # optional read-only web user
WEB_RO_PASS="${WEB_RO_PASS:-}"
WEB_REMOTE="${WEB_REMOTE:-no}"               # Allow remote access (all interfaces)
WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-9443}"     # HTTPS port of the console
WEB_URL=""

MEDIA=""
NON_INTERACTIVE="no"
NO_TUI="no"          # --no-tui forces plain text prompts (no whiptail/dialog)
UI_MODE="text"       # later set to "tui" if whiptail/dialog is usable
UI_TOOL=""           # "whiptail" or "dialog"
LOGFILE="/var/log/ibmmq-install-$(date +%Y%m%d-%H%M%S).log"
WORKDIR=""

#-------------------------------------------------------------------------------
# 0b) TUI detection (whiptail/dialog) – graphical console interface
#-------------------------------------------------------------------------------
UI_BACKTITLE="IBM MQ 9.4.x / 10.x Installation Script"

detect_tui() {
    [[ "$NO_TUI" == "yes" ]] && { UI_MODE="text"; return; }
    [[ "$NON_INTERACTIVE" == "yes" ]] && { UI_MODE="text"; return; }
    [[ -t 0 && -t 1 ]] || { UI_MODE="text"; return; }   # needs a real terminal

    if command -v whiptail >/dev/null 2>&1; then
        UI_TOOL="whiptail"
    elif command -v dialog >/dev/null 2>&1; then
        UI_TOOL="dialog"
    else
        # Try to quietly install whiptail (best effort)
        case "${PKG_FAMILY:-}" in
            rhel)   (dnf -y install newt 2>/dev/null || yum -y install newt 2>/dev/null) >/dev/null 2>&1 ;;
            suse)   zypper --non-interactive install newt >/dev/null 2>&1 ;;
            debian) (apt-get -y install whiptail >/dev/null 2>&1) ;;
        esac
        command -v whiptail >/dev/null 2>&1 && UI_TOOL="whiptail"
    fi

    if [[ -n "$UI_TOOL" ]] && tui_sanity_check; then
        UI_MODE="tui"
    else
        [[ -n "$UI_TOOL" ]] && warn "$UI_TOOL found, but the functional test failed in this terminal (TERM='${TERM:-unset}') – falling back to text mode."
        UI_TOOL=""
        UI_MODE="text"
    fi
}

# Checks whether the detected tool can actually be used for a full-screen
# display in the CURRENT terminal (not just whether the binary exists).
# Some environments (TERM not set, very small terminal, missing
# terminfo entries, certain serial/embedded consoles) do have
# whiptail/dialog installed, but cannot render full-screen dialogs –
# without this check the script would blindly rely on TUI and every
# following prompt could silently fail or stay empty.
tui_sanity_check() {
    local errfile rc
    errfile="$(mktemp /tmp/tui-check.XXXXXX 2>/dev/null)" || return 1
    "$UI_TOOL" --infobox "TUI test" 5 30 < /dev/tty > /dev/tty 2>"$errfile"
    rc=$?
    local haserr="no"
    [[ -s "$errfile" ]] && haserr="yes"
    rm -f "$errfile"
    [[ $rc -eq 0 && "$haserr" == "no" ]]
}

# Terminal size for whiptail/dialog (with sensible minimum/maximum values)
ui_dims() {
    local rows cols
    rows="$(tput lines 2>/dev/null || echo 24)"
    cols="$(tput cols  2>/dev/null || echo 80)"
    (( rows > 23 )) && rows=23
    (( cols > 100 )) && cols=100
    (( rows < 18 )) && rows=18
    (( cols < 70 )) && cols=70
    echo "$rows $cols"
}

ui_welcome() {
    [[ "$UI_MODE" == "tui" ]] || return 0
    local rc; read -r rows cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Welcome" \
        --msgbox "IBM MQ 9.4.x / 10.x installation and hardening script\n\nSupported: RHEL, SUSE Enterprise, Ubuntu, Raspberry Pi 4/5\n\nThe MQ version is determined by the supplied --media (9.4.x or 10.0.x).\n\nThe following screens ask for the queue manager parameters, security features and optional components.\n\nPress ENTER to continue." \
        "$rows" "$cols" 3>&1 1>&2 2>&3 || true
}

ui_menu_intro() {
    # Short progress/status screen between sections
    [[ "$UI_MODE" == "tui" ]] || return 0
    local text="$1"
    local rows cols; read -r rows cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "$text" \
        --infobox "$text ..." 6 "$cols" || true
    sleep 1
}

ui_summary_box() {
    # Shows a multi-line text in a scroll box (for the summary)
    [[ "$UI_MODE" == "tui" ]] || return 0
    local title="$1" content="$2"
    local rows cols; read -r rows cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "$title" \
        --scrolltext --msgbox "$content" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
}

# Runs a (potentially slow) command in the background and shows a progress
# indicator meanwhile, so it stays visible that the script is still running
# and not hanging. TUI mode: real whiptail progress bar (the percentage
# is estimated, since rpm/apt provide no easily parsable live percentage).
# Text mode: per-second heartbeat (dots). Returns the real exit code of
# the executed command.
run_with_progress() {
    local msg="$1"; shift
    "$@" >>"$LOGFILE" 2>&1 &
    local pid=$!

    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        (
            local pct=0
            while kill -0 "$pid" 2>/dev/null; do
                pct=$(( pct < 90 ? pct + 3 : 90 ))
                echo "$pct"
                sleep 1
            done
            echo 100
        ) | "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Please wait" \
                --gauge "$msg\n\n(running in the background - details in the logfile: $LOGFILE)" \
                12 "$cols" 0 2>/dev/null || true
    else
        echo -n "$msg "
        local elapsed=0
        while kill -0 "$pid" 2>/dev/null; do
            echo -n "."
            sleep 1
            elapsed=$((elapsed+1))
            # every 30s insert a timestamp, so long runs do not look like
            # an endless row of dots without any reference point
            if (( elapsed % 30 == 0 )); then
                echo -n " (${elapsed}s) "
            fi
        done
    fi

    wait "$pid"
    local rc=$?
    if [[ "$UI_MODE" != "tui" ]]; then
        if [[ $rc -eq 0 ]]; then echo " done."; else echo " ERROR (exit code $rc) – check logfile: $LOGFILE"; fi
    fi
    return $rc
}


# 1) Logging / helper functions
#-------------------------------------------------------------------------------
log()   { echo -e "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
error() { log "ERROR $*" >&2; }
die()   { error "$*"; exit 1; }

# Like die(), but for user aborts (Cancel/Esc, or an explicit "No"
# on a confirmation prompt) instead of real errors: does NOT end the whole
# script, but signals via the reserved exit code 99 to the
# outer loop (see run_main_flow at the very end of the script) to return
# to the main menu. Works regardless of how deeply nested the
# abort happens, since the outer loop runs the whole action in a
# subshell and evaluates its exit code.
cancel_to_menu() {
    warn "${1:-Aborted by user.}"
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Should never be reached in automation mode (ask()/ask_yes_no()/
        # ask_secret() return the default there immediately, without ever
        # showing an interactive dialog) - to be safe, still a
        # real error abort instead of a possible endless loop.
        die "Unexpected abort in automation mode: ${1:-Aborted by user.}"
    fi
    info "Back to the main menu ..."
    # IMPORTANT: "exit 99" alone would only end the INNERMOST subshell, which
    # e.g. every command substitution "X=\"\$(ask ...)\"" implicitly creates -
    # but ask()/ask_yes_no()/ask_secret() are called exactly like that
    # practically everywhere. Without a signal the caller would only receive this warn/info text
    # as its (wrong) return value and simply continue, instead of
    # returning to the main menu. The signal to the outer
    # run_main_flow subshell (see its BASHPID in RUN_MAIN_FLOW_PID)
    # reliably breaks through ANY nesting depth.
    if [[ -n "${RUN_MAIN_FLOW_PID:-}" ]]; then
        kill -s USR1 "$RUN_MAIN_FLOW_PID" 2>/dev/null || true
    fi
    exit 99
}

# Technically the same signal mechanism as cancel_to_menu(), but for
# a SUCCESSFULLY completed action (e.g. backup), after which the
# main menu should be shown again instead of ending the script - hence no
# "abort" message, but optionally a neutral note.
# shellcheck disable=SC2120  # the optional message argument is intentional
return_to_menu() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # In automation mode there is no interactive main menu that
        # one could return to - main_menu() would immediately return the same
        # MQ_MODE again and trigger the action again (endless loop).
        # Instead exit normally, as an automated call expects.
        exit 0
    fi
    [[ -n "${1:-}" ]] && info "$1"
    if [[ -n "${RUN_MAIN_FLOW_PID:-}" ]]; then
        kill -s USR1 "$RUN_MAIN_FLOW_PID" 2>/dev/null || true
    fi
    exit 99
}

# Purely informational line (section headers, notes) between two
# interactive prompts: in TUI mode write ONLY to the logfile, NOT to the
# terminal (otherwise a brief jump to the plain console between two
# whiptail dialogs, until a key is pressed). In text mode unchanged
# like info(), to terminal AND logfile.
narrate() {
    if [[ "$UI_MODE" == "tui" ]]; then
        echo "[$(date '+%F %T')] INFO  $*" >> "$LOGFILE" 2>/dev/null || true
    else
        info "$@"
    fi
}

on_error() {
    # $2 = exit code of the triggering command. 99 is reserved for
    # cancel_to_menu() (user abort, not a real error) - so print
    # no error message for it, even if the trap technically fires
    # (bash triggers the ERR trap for 'exit 99' itself, regardless of
    # whether it was disabled beforehand via 'trap - ERR').
    local line="$1" rc="${2:-1}"
    [[ "$rc" == "99" ]] && return 0
    error "Aborted at line $line. See logfile: $LOGFILE"
}
trap 'on_error $LINENO $?' ERR

cleanup() {
    if [[ -n "$WORKDIR" && -d "$WORKDIR" && "$WORKDIR" == /tmp/* ]]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage: sudo $0 --media <path> [options]

  --media <path>        Path to the MQ tar.gz OR to the extracted MQServer directory (required)
  --qmgr <name>         Name of the first queue manager (default: $MQ_QMGR_NAME)
  --port <port>         Listener port of the first QM (default: $MQ_LISTENER_PORT)
  --non-interactive     No prompts, uses defaults or environment variables
  --no-tui              Forces simple text prompts (no whiptail/dialog menu)
  -h | --help           This help

Graphical console interface (TUI):
  If whiptail or dialog is available and the script runs in a real
  terminal, menus/input fields/checkboxes (TUI) are shown instead of simple
  text prompts. If both are missing, the script installs
  "whiptail" if needed; if that fails, it automatically falls back to text prompts.
  The TUI can be explicitly disabled with --no-tui.

Main menu modes (selectable interactively, or unattended via MQ_MODE):
  install  New installation (install packages + set up queue managers)
  addqm    Add another queue manager to an existing installation
  backup   Back up one or all queue managers (config export via dmpmqcfg
           + data/log archive), no --media needed, see BACKUP_* variables
  restore  Restore a queue manager from a backup (configuration via
           MQSC re-import, or complete incl. data/log archive), no
           --media needed, source directory freely selectable, see RESTORE_* variables
  upgrade  Upgrade an existing installation to a newer version
           (stops all QMs, upgrades packages via rpm -Uvh/apt, restarts QMs
           -> automatic migration; --media = media of the NEW version)
  feature  Add a feature to an existing installation, e.g.
           MQTT/Telemetry (MQSeriesXRService) or Advanced Message Security
  uninstall  Completely remove the IBM MQ installation (all queue managers,
           packages, systemd units, aliases). No --media needed. Optionally
           also mqm user/group + /var/mqm via UNINSTALL_REMOVE_USER=yes.
           See UNINSTALL_* variables. IRREVERSIBLE - backup recommended first.
  Examples:
     sudo MQ_MODE=backup  BACKUP_QMS=all ./install-ibmmq.sh --non-interactive
     sudo MQ_MODE=restore RESTORE_SRC_DIR=/path/to/backups ./install-ibmmq.sh --non-interactive
     sudo MQ_MODE=upgrade ./install-ibmmq.sh --media <new-media> --non-interactive
     sudo MQ_MODE=uninstall UNINSTALL_CONFIRM=yes ./install-ibmmq.sh --non-interactive

Choosing the installation media interactively:
  If --media is not given and a mode (install/upgrade/feature) needs
  it, the script asks for the path to the tar.gz or the extracted directory directly
  within the menu flow (repeating on an invalid path) - but --media remains
  the fastest option for automation/scripting.

Multiple queue managers (1..x):
  Interactively the number is asked for; per QM name, port and channel.
  Unattended via the variable MQ_QMGRS (takes precedence over --qmgr/--port):
     MQ_QMGRS="NAME:PORT:CHANNEL,NAME:PORT:CHANNEL,..."
     Example: MQ_QMGRS="QM1:1414:APP.SVRCONN,QM2:1415:APP.SVRCONN"
     (port/channel optional; port otherwise starts at 1414, channel=$MQ_APP_CHANNEL)

Security/feature switches via environment variables, e.g.:
     SEC_TLS=yes SEC_AMS=yes INST_WEB=yes  ./install-ibmmq.sh ...
EOF
}

ask() {
    # ask "Question" "default"  -> returns the answer on stdout
    local prompt="$1" default="$2" answer
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        echo "$default"; return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        answer="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Input" \
            --inputbox "$prompt" 10 "$cols" "$default" 3>&1 1>&2 2>&3)"
        local rc=$?
        [[ $rc -ne 0 ]] && cancel_to_menu "Aborted by user (input cancelled)."
        echo "${answer:-$default}"
        return
    fi
    read -r -p "$prompt [$default]: " answer < /dev/tty || true
    echo "${answer:-$default}"
}

ask_yes_no() {
    # ask_yes_no "Question" "yes|no" -> returns yes/no
    local prompt="$1" default="$2" answer
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        echo "$default"; return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        local defbtn=(); [[ "$default" == "no" ]] && defbtn=(--defaultno)
        # IMPORTANT: explicitly against /dev/tty instead of the default descriptors, since
        # ask_yes_no is ALWAYS called as "X=$(ask_yes_no ...)". Without the
        # /dev/tty redirection, whiptail's own screen rendering
        # (escape sequences) would be captured into the variable instead of
        # appearing on the terminal (--yesno deliberately does NOT use the 3>&1 1>&2 2>&3
        # trick, since it returns no text, only the exit code).
        # IMPORTANT: whiptail returns 0=Yes, 1=No, 255=ESC (abort) - these three
        # cases must be distinguished ("|| rc=\$?" instead of if/then/else,
        # otherwise ESC would wrongly be treated like an explicit "No" and
        # e.g. at the final question only lead to adjusting the settings
        # instead of really aborting to the main menu).
        local rc=0
        "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Confirmation" \
            "${defbtn[@]}" --yesno "$prompt" 10 "$cols" < /dev/tty > /dev/tty 2>&1 || rc=$?
        case $rc in
            0) echo "yes" ;;
            1) echo "no" ;;
            *) cancel_to_menu "Aborted by user (ESC)." ;;
        esac
        return
    fi
    read -r -p "$prompt (yes/no) [$default]: " answer < /dev/tty || true
    answer="${answer:-$default}"
    case "${answer,,}" in
        y|yes|j|ja) echo "yes" ;;
        *)          echo "no"  ;;
    esac
}

ask_secret() {
    # ask_secret "Prompt" "$current_value"
    # -> hidden input with repetition; prompts go to /dev/tty,
    #    only the password is returned on stdout.
    local prompt="$1" current="$2" p1 p2
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        if [[ -n "$current" ]]; then
            echo "$current"
        else
            # No password given -> generate a secure random password
            openssl rand -base64 15 2>/dev/null | tr -d '\n' || echo "Chg-Me-$(date +%s)"
        fi
        return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        while true; do
            p1="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Password" \
                --passwordbox "$prompt" 10 "$cols" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
            p2="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Password" \
                --passwordbox "$prompt (repeat)" 10 "$cols" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
            if [[ -z "$p1" ]]; then
                "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox "Password must not be empty." 8 60 < /dev/tty > /dev/tty 2>&1 || true
                continue
            fi
            if [[ "$p1" != "$p2" ]]; then
                "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox "Passwords do not match. Please try again." 8 60 < /dev/tty > /dev/tty 2>&1 || true
                continue
            fi
            echo "$p1"; return
        done
    fi
    while true; do
        read -r -s -p "$prompt: " p1 < /dev/tty; echo > /dev/tty
        read -r -s -p "$prompt (repeat): " p2 < /dev/tty; echo > /dev/tty
        if [[ "$p1" != "$p2" ]]; then
            echo "  -> Passwords do not match. Please try again." > /dev/tty; continue
        fi
        if [[ -z "$p1" ]]; then
            echo "  -> Password must not be empty." > /dev/tty; continue
        fi
        echo "$p1"; return
    done
}

parse_qmgr_spec() {
    # Parses "NAME[:PORT[:CHANNEL]]" into the QMGR_* arrays.
    # PORT can be given as PORT_START[-PORT_END].
    # CHANNEL is optional (default: MQ_APP_CHANNEL).
    local spec="$1" entry idx=0 name port chan
    local OLDIFS="$IFS"; IFS=','
    for entry in $spec; do
        IFS="$OLDIFS"
        entry="$(echo "$entry" | tr -d '[:space:]')"
        [[ -z "$entry" ]] && { IFS=','; continue; }
        name="${entry%%:*}"
        local rest="${entry#*:}"
        if [[ "$rest" == "$entry" ]]; then
            # Only the name given
            port=$(( 1414 + idx )); chan="$MQ_APP_CHANNEL"
        else
            port="${rest%%:*}"
            local rest2="${rest#*:}"
            if [[ "$rest2" == "$rest" ]]; then
                # Name:Port
                chan="$MQ_APP_CHANNEL"
            else
                chan="$rest2"
            fi
            if [[ "$port" =~ ^([0-9]+)(-([0-9]+))?$ ]]; then
                # Port range given -> fill sequentially
                local start="${BASH_REMATCH[1]}" end="${BASH_REMATCH[3]}"
                [[ -z "$end" ]] && end="$start"
                for (( p=start; p<=end; p++ )); do
                    QMGR_NAMES+=("$name"); QMGR_PORTS+=("$p"); QMGR_CHANNELS+=("$chan")
                done
                (( idx += end - start + 1 ))
                continue
            fi
        fi
        QMGR_NAMES+=("$name"); QMGR_PORTS+=("${port:-$(( 1414 + idx ))}"); QMGR_CHANNELS+=("${chan:-$MQ_APP_CHANNEL}")
        idx=$(( idx + 1 )); IFS=','
    done
    IFS="$OLDIFS"
    [[ ${#QMGR_NAMES[@]} -ge 1 ]] || die "MQ_QMGRS could not be parsed: '$spec'"
}

#-------------------------------------------------------------------------------
# 2) Argument parsing
#-------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --media)            MEDIA="$2"; shift 2 ;;
        --qmgr)             MQ_QMGR_NAME="$2"; shift 2 ;;
        --port)             MQ_LISTENER_PORT="$2"; shift 2 ;;
        --non-interactive)  NON_INTERACTIVE="yes"; shift ;;
        --no-tui)           NO_TUI="yes"; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "Unknown option: $1 (see --help)" ;;
    esac
done

#-------------------------------------------------------------------------------
# 3) Preconditions
#-------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "Please run as root or with sudo."
touch "$LOGFILE" 2>/dev/null || LOGFILE="/tmp/$(basename "$LOGFILE")"
info "Logfile: $LOGFILE"
info "IBM MQ 9.4.x / 10.x installation script started."

#-------------------------------------------------------------------------------
# 4) OS and architecture detection
#-------------------------------------------------------------------------------
detect_platform() {
    [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release."
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_LIKE="${ID_LIKE:-}"
    OS_VERSION="${VERSION_ID:-}"
    ARCH="$(uname -m)"

    case "$ARCH" in
        x86_64|amd64) ARCH_CLASS="x86_64" ;;
        aarch64|arm64) ARCH_CLASS="arm64" ;;
        armv7l|armv6l) ARCH_CLASS="arm32" ;;
        *) die "Unsupported architecture: $ARCH" ;;
    esac

    # Determine package format
    if [[ "$OS_ID" =~ ^(rhel|centos|rocky|almalinux|fedora)$ ]] || [[ "$OS_LIKE" =~ rhel ]]; then
        PKG_FORMAT="rpm"; PKG_FAMILY="rhel"
    elif [[ "$OS_ID" =~ ^(sles|sled|opensuse.*|suse)$ ]] || [[ "$OS_LIKE" =~ suse ]]; then
        PKG_FORMAT="rpm"; PKG_FAMILY="suse"
    elif [[ "$OS_ID" =~ ^(ubuntu|debian|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; then
        PKG_FORMAT="deb"; PKG_FAMILY="debian"
    else
        die "Unsupported distribution: $OS_ID ($OS_LIKE)"
    fi

    IS_RPI="no"
    if grep -qi "raspberry" /proc/cpuinfo 2>/dev/null || \
       grep -qi "raspberry" /sys/firmware/devicetree/base/model 2>/dev/null; then
        IS_RPI="yes"
    fi

    info "Distribution : $OS_ID $OS_VERSION  (family: $PKG_FAMILY, format: $PKG_FORMAT)"
    info "Architecture : $ARCH  (class: $ARCH_CLASS)"
    info "Raspberry Pi : $IS_RPI"

    # Warnings for Raspberry Pi
    if [[ "$IS_RPI" == "yes" && "$ARCH_CLASS" == "arm32" ]]; then
        warn "32-bit Raspberry Pi detected. IBM MQ ARM32 is only 'as-is' (without official support)."
        warn "Recommendation: use a 64-bit OS (Raspberry Pi OS 64-bit or Ubuntu ARM64) for the ARM64 build."
        if [[ "$(ask_yes_no 'Continue anyway?' 'no')" != "yes" ]]; then
            die "Aborted by user (32-bit RPi)."
        fi
    fi
    if [[ "$ARCH_CLASS" == "arm64" ]]; then
        info "Using the ARM64 build (officially available since IBM MQ 9.4.1 for Ubuntu/RPi 64-bit, continued in 10.0.x)."
    fi
}
detect_platform

#-------------------------------------------------------------------------------
# 5) Install package prerequisites (tar, libs)
#-------------------------------------------------------------------------------
install_prereqs() {
    info "Installing base prerequisites ..."
    case "$PKG_FAMILY" in
        rhel)
            local mgr="dnf"; command -v dnf >/dev/null 2>&1 || mgr="yum"
            $mgr -y install tar bash coreutils which findutils >>"$LOGFILE" 2>&1 || \
                warn "Prerequisites could not be installed completely (possibly no repo)."
            ;;
        suse)
            zypper --non-interactive install tar bash coreutils which findutils >>"$LOGFILE" 2>&1 || \
                warn "Prerequisites could not be installed completely."
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update >>"$LOGFILE" 2>&1 || warn "apt-get update failed."
            apt-get -y install tar bash coreutils findutils >>"$LOGFILE" 2>&1 || \
                warn "Prerequisites could not be installed completely."
            ;;
    esac
}
install_prereqs

#-------------------------------------------------------------------------------
# 5b) Enable TUI (whiptail/dialog) and show the welcome screen
#-------------------------------------------------------------------------------
detect_tui
if [[ "$UI_MODE" == "tui" ]]; then
    info "Graphical console interface (TUI) active: $UI_TOOL"
else
    info "Text mode active (no whiptail/dialog available or --no-tui/--non-interactive set)."
fi
ui_welcome

#-------------------------------------------------------------------------------
# 5c) Main menu – choose the operating mode
#-------------------------------------------------------------------------------
MODE="install"   # install | addqm | upgrade | feature | backup | restore | uninstall | objects | tls

mq_is_installed() {
    [[ -x "$MQ_INSTALL_PATH/bin/setmqenv" ]]
}

show_status_menu() {
    echo
    info "==== Status of existing queue managers ===="
    if ! id mqm >/dev/null 2>&1; then
        warn "User 'mqm' does not exist – IBM MQ does not seem to be installed on this host."
        return 0
    fi
    source_mqenv 2>/dev/null || true

    while true; do
        # Query dspmq with status AND associated installation (two -o
        # parameters can be combined) - important to immediately see "orphaned" QMs
        # (associated with a version that is no longer installed).
        local raw
        raw="$(su -s /bin/bash mqm -c "dspmq -o status -o installation" 2>&1)" || true

        local -a qm_names=() qm_status=() qm_inst=()
        if [[ -n "$raw" ]]; then
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                local name status inst
                name="$(echo "$line" | sed -n 's/.*QMNAME(\([^)]*\)).*/\1/p')"
                [[ -n "$name" ]] || continue
                status="$(echo "$line" | sed -n 's/.*STATUS(\([^)]*\)).*/\1/p')"
                inst="$(echo "$line" | sed -n 's/.*INSTNAME(\([^)]*\)).*/\1/p')"
                qm_names+=("$name")
                qm_status+=("${status:-unknown}")
                qm_inst+=("${inst:-unknown}")
            done <<< "$raw"
        fi

        local display
        if [[ ${#qm_names[@]} -eq 0 ]]; then
            display="No queue managers found on this host."
        else
            display="$(printf '%-20s %-22s %-20s\n' 'QUEUE MANAGER' 'STATUS' 'INSTALLATION')"
            display+=$'\n'"$(printf -- '-%.0s' {1..62})"
            local i
            for i in "${!qm_names[@]}"; do
                display+=$'\n'"$(printf '%-20s %-22s %-20s' "${qm_names[$i]}" "${qm_status[$i]}" "${qm_inst[$i]}")"
            done
        fi
        echo "$display" | tee -a "$LOGFILE"

        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Queue manager status" \
                --msgbox "$display" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
        fi

        [[ ${#qm_names[@]} -eq 0 ]] && return 0

        if [[ "$(ask_yes_no 'Start or stop a queue manager?' 'no')" != "yes" ]]; then
            return 0
        fi

        # ---- Select queue manager ----
        local sel_qm=""
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local items=()
            for i in "${!qm_names[@]}"; do
                items+=("${qm_names[$i]}" "${qm_status[$i]} / ${qm_inst[$i]}")
            done
            sel_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Select queue manager" \
                --menu "Which queue manager should be managed?" "$rows" "$cols" "${#qm_names[@]}" \
                "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        else
            for i in "${!qm_names[@]}"; do
                echo "  $((i+1))) ${qm_names[$i]}  (${qm_status[$i]}, ${qm_inst[$i]})"
            done
            local choice
            read -r -p "Choose number: " choice < /dev/tty || true
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#qm_names[@]}" ]]; then
                sel_qm="${qm_names[$((choice-1))]}"
            fi
        fi
        [[ -n "$sel_qm" ]] || cancel_to_menu "No queue manager selected."

        # ---- Select action ----
        local action="start"
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            action="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Action for $sel_qm" \
                --menu "Choose action for '$sel_qm':" "$rows" "$cols" 2 \
                "start" "Start" \
                "stop"  "Stop" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        else
            echo "  1) Start"
            echo "  2) Stop"
            local achoice
            read -r -p "Action [1]: " achoice < /dev/tty || true
            [[ "$achoice" == "2" ]] && action="stop"
        fi

        if [[ "$action" == "start" ]]; then
            manage_start_qmgr "$sel_qm"
        else
            info "Stopping '$sel_qm' (endmqm -w, controlled) ..."
            if su -s /bin/bash mqm -c "endmqm -w '$sel_qm'" >>"$LOGFILE" 2>&1; then
                info "'$sel_qm' stopped."
            else
                warn "'$sel_qm' could not be stopped in a controlled way (endmqm -w)."
                if [[ "$(ask_yes_no "Force an immediate stop (endmqm -i) for '$sel_qm'?" 'no')" == "yes" ]]; then
                    su -s /bin/bash mqm -c "endmqm -i '$sel_qm'" >>"$LOGFILE" 2>&1 \
                        && info "'$sel_qm' stopped via 'endmqm -i'." \
                        || warn "'$sel_qm' could not be stopped even with 'endmqm -i'. Check the logfile."
                fi
            fi
        fi
        # Loop: show the refreshed status display again
    done
}

# "Soft" variant of start_qmgr_robust for the interactive status/
# management view: warns on failure instead of ending the whole script via die()
# (here a failed start should not abort the menu
# session, the user should simply be able to continue working).
manage_start_qmgr() {
    local qm="$1"
    info "Starting '$qm' ..."
    local out rc=0
    out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    if [[ $rc -eq 0 ]]; then
        info "'$qm' started."
        return 0
    fi
    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        warn "'$qm' is associated with a different (possibly no longer installed) MQ installation."
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]] && [[ "$(ask_yes_no "Try to associate '$qm' with the current installation '$inst_name' (setmqm) and start it again?" 'yes')" == "yes" ]]; then
            info "Associating '$qm' with installation '$inst_name' (setmqm) ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                rc=0
                out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
                echo "$out" >> "$LOGFILE"
                if [[ $rc -eq 0 ]]; then
                    info "'$qm' started after re-association."
                    return 0
                fi
            fi
            warn "setmqm/restart failed."
        fi
    fi
    warn "'$qm' could not be started. Check logfile: $LOGFILE"
    return 1
}

show_aliases_menu() {
    echo
    info "==== Convenience aliases ===="
    local out=""

    local afile="/etc/profile.d/mqm-aliases.sh"
    if [[ -f "$afile" ]]; then
        local anames
        anames="$(grep '^alias ' "$afile" 2>/dev/null | sed "s/^alias \([^=]*\)=.*/\1/" | tr '\n' ' ')"
        out+="Available aliases (from $afile):"$'\n'"  ${anames:-<none found>}"
        out+=$'\n\n'"Effective after a new login (SSH login or 'sudo su -')."
        out+=$'\n'"View full commands: cat $afile"
    else
        out+="No aliases created (file '$afile' does not exist)."
    fi

    echo "$out" | tee -a "$LOGFILE"
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Aliases" \
            --msgbox "$out" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
    fi
    return 0
}

main_menu() {
    # Automation (--non-interactive) skips the menu.
    # MQ_MODE also allows automation for addqm/upgrade/feature (default: install).
    [[ "$NON_INTERACTIVE" == "yes" ]] && { MODE="$MQ_MODE"; return; }

    local installed="no"

    while true; do
        mq_is_installed && installed="yes" || installed="no"

        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local choice
            choice="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Main menu" \
                --cancel-button "Exit" \
                --menu "IBM MQ already installed: $installed\n\nPlease choose an action:" \
                "$rows" "$cols" 12 \
                "1" "New installation (install packages + set up queue managers)" \
                "2" "Add another queue manager to an existing installation" \
                "3" "Back up one or all queue managers" \
                "4" "Restore a queue manager from a backup" \
                "5" "Upgrade an existing installation to a newer version" \
                "6" "Install an add-on feature (MQTT/Telemetry, AMS)" \
                "7" "Completely remove the IBM MQ installation (uninstall)" \
                "8" "Create objects for a queue manager (channels, listeners)" \
                "9" "SSL/TLS management (certificates, trust chain)" \
                "10" "Show status of existing queue managers" \
                "11" "Show alias overview" \
                "12" "Exit" \
                3>&1 1>&2 2>&3)" || { info "Aborted by user."; exit 0; }
            case "$choice" in
                1) MODE="install" ;;
                2) MODE="addqm" ;;
                3) MODE="backup" ;;
                4) MODE="restore" ;;
                5) MODE="upgrade" ;;
                6) MODE="feature" ;;
                7) MODE="uninstall" ;;
                8) MODE="objects" ;;
                9) MODE="tls" ;;
                10) show_status_menu; continue ;;
                11) show_aliases_menu; continue ;;
                *) info "Exited."; exit 0 ;;
            esac
        else
            echo
            echo "==================================================================="
            echo " IBM MQ 9.4.x / 10.x Installation Script – Main menu"
            echo " (IBM MQ already installed: $installed)"
            echo "==================================================================="
            echo "  1) New installation (install packages + set up queue managers)"
            echo "  2) Add another queue manager to an existing installation"
            echo "  3) Back up one or all queue managers"
            echo "  4) Restore a queue manager from a backup"
            echo "  5) Upgrade an existing installation to a newer version"
            echo "  6) Install an add-on feature (MQTT/Telemetry, AMS)"
            echo "  7) Completely remove the IBM MQ installation (uninstall)"
            echo "  8) Create objects for a queue manager (channels, listeners)"
            echo "  9) SSL/TLS management (certificates, trust chain)"
            echo " 10) Show status of existing queue managers"
            echo " 11) Show alias overview"
            echo " 12) Exit"
            echo "==================================================================="
            local choice
            read -r -p "Choice [1]: " choice < /dev/tty || true
            case "${choice:-1}" in
                1) MODE="install" ;;
                2) MODE="addqm" ;;
                3) MODE="backup" ;;
                4) MODE="restore" ;;
                5) MODE="upgrade" ;;
                6) MODE="feature" ;;
                7) MODE="uninstall" ;;
                8) MODE="objects" ;;
                9) MODE="tls" ;;
                10) show_status_menu; continue ;;
                11) show_aliases_menu; continue ;;
                12) info "Exited."; exit 0 ;;
                *) warn "Invalid choice, starting new installation."; MODE="install" ;;
            esac
        fi
        break
    done

    if [[ "$MODE" =~ ^(addqm|upgrade|feature|backup|restore|uninstall|objects|tls)$ ]] && ! mq_is_installed; then
        warn "No existing IBM MQ installation found under '$MQ_INSTALL_PATH'."
        if [[ "$UI_MODE" == "tui" ]]; then
            "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox \
                "No existing IBM MQ installation found.\nA new installation will be performed instead." 8 70 || true
        fi
        info "Falling back to new installation."
        MODE="install"
    fi

    local _tty_stdin="no" _tty_stdout="no"
    [[ -t 0 ]] && _tty_stdin="yes"
    [[ -t 1 ]] && _tty_stdout="yes"
    info "Selected mode: $MODE (UI_MODE=$UI_MODE, UI_TOOL=${UI_TOOL:-none}, TTY: stdin=$_tty_stdin stdout=$_tty_stdout)"
}

#-------------------------------------------------------------------------------
# 5e) Reusable installation functions (defined early, so they can be used by
#     perform_upgrade()/perform_feature_install() AND by the normal install flow
#     further below)
#-------------------------------------------------------------------------------
prepare_media() {
    info "Preparing installation media ..."
    if [[ -d "$MEDIA" ]]; then
        # Directory: either already extracted media (MQServer folder
        # up to 5 levels deep, case-insensitive), or a
        # directory that still contains an unopened tar.gz.
        if [[ -f "$MEDIA/mqlicense.sh" ]]; then
            MQ_SRC="$MEDIA"
        elif [[ -f "$MEDIA/MQServer/mqlicense.sh" ]]; then
            MQ_SRC="$MEDIA/MQServer"
        else
            MQ_SRC="$(find "$MEDIA" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
            if [[ -z "$MQ_SRC" ]]; then
                # No extracted media found - is there possibly an
                # unopened tar.gz directly in this directory?
                local found_tars found_tar tar_count
                found_tars="$(find "$MEDIA" -maxdepth 2 -iname '*.tar.gz' 2>/dev/null | sort)"
                tar_count="$(echo "$found_tars" | grep -c . || true)"
                if [[ "$tar_count" -ge 1 ]]; then
                    found_tar="$(echo "$found_tars" | head -n1)"
                    if [[ "$tar_count" -gt 1 ]]; then
                        warn "Several .tar.gz files found under '$MEDIA', using the first one (alphabetically):"
                        echo "$found_tars" | sed 's/^/  /' | tee -a "$LOGFILE"
                    fi
                    info "No extracted media found, but an unopened archive was detected: $found_tar"
                    WORKDIR="$(mktemp -d /tmp/ibmmq.XXXXXX)"
                    narrate "Extracting $found_tar to $WORKDIR (GNU tar) ..."
                    run_with_progress "Extracting installation media ..." tar -xzf "$found_tar" -C "$WORKDIR" \
                        || die "Extracting '$found_tar' failed. Check logfile: $LOGFILE"
                    MQ_SRC="$(find "$WORKDIR" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
                fi
            fi
        fi
    else
        # MEDIA is a file -> treat it directly as tar.gz (GNU tar strictly required)
        WORKDIR="$(mktemp -d /tmp/ibmmq.XXXXXX)"
        narrate "Extracting $MEDIA to $WORKDIR (GNU tar) ..."
        run_with_progress "Extracting installation media ..." tar -xzf "$MEDIA" -C "$WORKDIR" \
            || die "Extracting the installation media failed. Check logfile: $LOGFILE"
        MQ_SRC="$(find "$WORKDIR" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
    fi

    if [[ -z "${MQ_SRC:-}" || ! -f "$MQ_SRC/mqlicense.sh" ]]; then
        warn "Could not find mqlicense.sh under '$MEDIA' (searched up to 5 directory levels, also searched for *.tar.gz)."
        warn "Actual content of '$MEDIA' (2 levels deep):"
        find "$MEDIA" -maxdepth 2 2>/dev/null | sed 's/^/  /' | tee -a "$LOGFILE" || true
        die "mqlicense.sh not found. Please point --media either directly to the .tar.gz file (e.g. --media /install/MQServer-9.4.0.x-Linux.tar.gz) or to the already extracted directory containing mqlicense.sh – see the directory content above."
    fi
    info "Installation source: $MQ_SRC"
}

accept_license() {
    info "Accepting the IBM MQ license agreement ..."
    ( cd "$MQ_SRC" && ./mqlicense.sh -accept >>"$LOGFILE" 2>&1 ) || \
        die "License acceptance failed. Check the logfile."
    info "License accepted."
}

# Sources IBM's setmqenv, to make PATH/environment for the MQ commands
# (dspmqver, crtmqm, runmqsc, ...) available in the current shell process.
# IMPORTANT: setmqenv is not written for 'set -u' (it references
# e.g. $ZSH_EVAL_CONTEXT unguarded for shell detection). Since we include it
# via 'source', it runs in the same shell process and would inherit our
# 'set -u' -> immediate abort with "unbound variable". So relax it
# temporarily while sourcing and restore it afterwards.
source_mqenv() {
    local rc=0
    set +u
    # shellcheck disable=SC1090
    . "$MQ_INSTALL_PATH/bin/setmqenv" -s || rc=$?
    set -u
    return $rc
}

post_install_setup() {
    info "Configuring installation ..."
    if [[ -x "$MQ_INSTALL_PATH/bin/setmqinst" ]]; then
        # Only set as primary installation if none exists yet
        if ! "$MQ_INSTALL_PATH/bin/dspmqinst" 2>/dev/null | grep -qi "Primary:.*Yes"; then
            "$MQ_INSTALL_PATH/bin/setmqinst" -i -p "$MQ_INSTALL_PATH" >>"$LOGFILE" 2>&1 || \
                warn "setmqinst (primary installation) failed – possibly one already exists."
        fi
    fi
    # Make the MQ environment available system-wide
    cat > /etc/profile.d/mqenv.sh <<EOF
# IBM MQ environment
if [ -f "$MQ_INSTALL_PATH/bin/setmqenv" ]; then
    # relax set -u if needed: setmqenv references \$ZSH_EVAL_CONTEXT unguarded
    case "\$-" in *u*) __mqenv_had_u=1; set +u ;; *) __mqenv_had_u=0 ;; esac
    . "$MQ_INSTALL_PATH/bin/setmqenv" -s >/dev/null 2>&1
    [ "\$__mqenv_had_u" = "1" ] && set -u
    unset __mqenv_had_u
fi
EOF
    source_mqenv
    info "IBM MQ version:"
    dspmqver | tee -a "$LOGFILE"
    MQ_INSTALLED_VERSION="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
}

# Starts a queue manager via strmqm. Detects the case where the QM is associated
# with a different (possibly no longer installed) MQ installation
# (AMQ7204E - typically happens when a different MQ version was installed
# earlier and the QM was created/started with it). In that case,
# after confirmation, it tries to associate the QM with the current
# installation via 'setmqm' and then start it again, instead of just aborting
# with a generic error message.
start_qmgr_robust() {
    local qm="$1"
    local out rc=0
    out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    [[ $rc -eq 0 ]] && return 0

    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        warn "Queue manager '$qm' is associated with a different (possibly no longer installed) MQ installation."
        warn "This typically happens when a different MQ version was installed earlier and this"
        warn "queue manager was created/last started with it."
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]] && [[ "$(ask_yes_no "Try to associate '$qm' with the current installation '$inst_name' (setmqm) and start it again?" 'yes')" == "yes" ]]; then
            info "Associating '$qm' with installation '$inst_name' (setmqm) ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                info "Starting '$qm' again ..."
                if su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1; then
                    info "'$qm' started successfully after re-association."
                    return 0
                fi
            fi
            warn "setmqm/restart failed."
        fi
        die "'$qm' is associated with a different installation and could not be started. Manual options: (1) 'setmqm -m $qm -i <installation name>' to associate it with the current installation, then 'strmqm $qm'. (2) If '$qm' contains only test data: remove the data under /var/mqm/qmgrs/$qm and /var/mqm/log/$qm according to the IBM documentation (dltmqm or manually) and recreate the QM via the main menu."
    fi
    die "strmqm for '$qm' failed. Check logfile: $LOGFILE"
}

# Stops (if necessary) and cleanly deletes a queue manager (dltmqm).
# Detects the same "different installation" case as start_qmgr_robust and
# tries setmqm beforehand in that case, so that dltmqm does not fail needlessly.
# On failure does NOT give up the whole uninstallation (warn instead of die),
# since as many QMs as possible should be removed, even if one hangs.
delete_qmgr_robust() {
    local qm="$1"
    su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 || true

    local out rc=0
    out="$(su -s /bin/bash mqm -c "dltmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    if [[ $rc -eq 0 ]]; then
        info "Queue manager '$qm' deleted."
        return 0
    fi

    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]]; then
            warn "'$qm' is associated with a different installation - trying re-association (setmqm) before deleting ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                rc=0
                out="$(su -s /bin/bash mqm -c "dltmqm '$qm'" 2>&1)" || rc=$?
                echo "$out" >> "$LOGFILE"
                if [[ $rc -eq 0 ]]; then
                    info "Queue manager '$qm' deleted after re-association."
                    return 0
                fi
            fi
        fi
    fi

    warn "'$qm' could not be removed via dltmqm (check logfile). Removing directories manually ..."
    rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
        && info "Directories of '$qm' removed manually (the mqs.ini entry may remain)." \
        || warn "Manual removal of the directories of '$qm' partially failed."
    return 1
}

# Names of all queue managers known on this host (one name per line, empty if none/no mqm user)
get_all_qm_names() {
    id mqm >/dev/null 2>&1 || return 0
    su -s /bin/bash mqm -c "dspmq" 2>/dev/null | sed -n "s/.*QMNAME(\([^)]*\)).*/\1/p" || true
}

# Returns "yes" if IBM MQ packages are already installed on this host
# (regardless of version). Important for the "install" mode, which
# is intended for a fresh host: apt/rpm would otherwise possibly silently
# downgrade or even remove existing packages if their version
# or selection does not match this run.
check_existing_mq_packages() {
    local names=""
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        names="$(rpm -qa --qf '%{NAME}\n' 2>>"$LOGFILE" | grep '^MQSeries' || true)"
    else
        names="$(dpkg-query -W -f='${Package}\n' 2>>"$LOGFILE" | grep '^ibmmq-' || true)"
    fi
    if [[ -n "$names" ]]; then
        echo "yes"
    else
        echo "no"
    fi
}

# Determines the currently installed MQ version from the runtime package
# (e.g. "9.4.4.0"). Empty if not installed/not determinable.
get_installed_mq_version() {
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        rpm -q --qf '%{VERSION}\n' MQSeriesRuntime 2>/dev/null | head -n1
    else
        dpkg-query -W -f='${Version}\n' ibmmq-runtime 2>/dev/null | head -n1
    fi
}

# Determines the MQ version contained in the supplied installation media
# from the file name of the runtime package in $MQ_SRC
# (e.g. "ibmmq-runtime_9.4.1.0_amd64.deb" -> "9.4.1.0"). Empty if not determinable.
get_media_mq_version() {
    local f
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        f="$(find "$MQ_SRC" -maxdepth 1 -name 'MQSeriesRuntime-*.rpm' 2>/dev/null | head -n1)"
    else
        f="$(find "$MQ_SRC" -maxdepth 1 -name 'ibmmq-runtime_*.deb' 2>/dev/null | head -n1)"
    fi
    [[ -n "$f" ]] && basename "$f" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

# Compares the media version against the installed version. Returns "yes"
# if the media would be a LOWER version than the installed one (i.e.
# a real downgrade, which IBM MQ fundamentally does NOT support and which
# the package installation script itself hard-refuses - regardless of
# apt/rpm options such as --allow-downgrades). "no" if equal, newer, or
# not determinable (then rather let it through and let the actual
# package installation decide, instead of blocking wrongly).
would_be_real_downgrade() {
    local installed_ver="$1" media_ver="$2"
    [[ -n "$installed_ver" && -n "$media_ver" ]] || { echo "no"; return; }
    if [[ "$PKG_FORMAT" == "deb" ]] && command -v dpkg >/dev/null 2>&1; then
        if dpkg --compare-versions "$media_ver" lt "$installed_ver" 2>/dev/null; then
            echo "yes"; return
        fi
    else
        # Simple, lossless version comparison via 'sort -V' (works
        # for the usual x.y.z.w form equally for rpm and deb).
        local lower
        lower="$(printf '%s\n%s\n' "$media_ver" "$installed_ver" | sort -V | head -n1)"
        if [[ "$lower" == "$media_ver" && "$media_ver" != "$installed_ver" ]]; then
            echo "yes"; return
        fi
    fi
    echo "no"
}

# Asks (if MEDIA is empty and interactive) for the installation media and
# validates the path; repeats the prompt on invalid input.
ensure_media_path() {
    local mode_label="$1"
    if [[ -z "$MEDIA" ]]; then
        [[ "$NON_INTERACTIVE" == "yes" ]] && { usage; die "--media is required for mode '$mode_label'."; }
        local prompt="Path to the MQ tar.gz OR to the extracted MQServer directory"
        while true; do
            MEDIA="$(ask "$prompt" "$MEDIA")"
            if [[ -z "$MEDIA" ]]; then
                narrate "No path given - asking again."
                prompt="Please enter a path. Path to the MQ tar.gz OR to the extracted MQServer directory"
                continue
            fi
            if [[ ! -e "$MEDIA" ]]; then
                narrate "Path '$MEDIA' does not exist - asking again."
                prompt="Path does not exist, please try again. Path to the MQ tar.gz OR to the extracted MQServer directory"
                MEDIA=""
                continue
            fi
            break
        done
    fi
    [[ -n "$MEDIA" ]] || { usage; die "--media is required for mode '$mode_label'."; }
    [[ -e "$MEDIA" ]] || die "Media path does not exist: $MEDIA"
}

#-------------------------------------------------------------------------------
# 5f) Upgrade an existing installation to a newer version
#-------------------------------------------------------------------------------
upgrade_rpm_packages() {
    narrate "Determining installed RPM components for the upgrade ..."
    local installed_names; installed_names="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep '^MQSeries' || true)"
    [[ -n "$installed_names" ]] || die "No installed MQSeries RPM packages found – upgrade not possible."
    local files=() name f
    for name in $installed_names; do
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${name}-*.rpm" | head -n1 || true)"
        if [[ -n "$f" ]]; then
            files+=("$f")
        else
            warn "No upgrade package for '$name' found in the media – skipping."
        fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "No matching upgrade packages found in the media."
    narrate "Upgrading ${#files[@]} packages via 'rpm -Uvh' (upgrade, NOT -ivh) ..."
    run_with_progress "Upgrading ${#files[@]} RPM package(s) (may take 1-2 minutes) ..." \
        rpm -Uvh "${files[@]}" || die "RPM upgrade failed. Check logfile: $LOGFILE"
    info "RPM packages upgraded successfully."
}

upgrade_deb_packages() {
    narrate "Determining installed DEB components for the upgrade ..."
    local installed_names; installed_names="$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep '^ibmmq-' || true)"
    [[ -n "$installed_names" ]] || die "No installed ibmmq-* packages found – upgrade not possible."
    local files=() name f
    for name in $installed_names; do
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${name}_*.deb" | head -n1 || true)"
        if [[ -n "$f" ]]; then
            files+=("$f")
        else
            warn "No upgrade package for '$name' found in the media – skipping."
        fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "No matching upgrade packages found in the media."
    export DEBIAN_FRONTEND=noninteractive
    narrate "Upgrading ${#files[@]} packages via apt-get install (dpkg upgrades packages of the same name automatically) ..."
    run_with_progress "Upgrading ${#files[@]} DEB package(s) (may take 1-2 minutes) ..." \
        apt-get -y install "${files[@]}" || die "DEB upgrade failed. Check logfile: $LOGFILE"
    info "DEB packages upgraded successfully."
}

perform_upgrade() {
    echo
    narrate "==== Upgrade of an existing IBM MQ installation ===="
    [[ -n "$MEDIA" ]] || { usage; die "--media is required (mode: upgrade)."; }
    [[ -e "$MEDIA" ]] || die "Media path does not exist: $MEDIA"

    source_mqenv 2>/dev/null || true
    local old_version; old_version="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
    narrate "Currently installed version: ${old_version:-unknown}"

    # Prepare the media and DETERMINE the version BEFORE anything is stopped:
    # this way a real downgrade (not supported by IBM MQ) can be
    # caught without having already stopped queue managers/mqweb.
    prepare_media
    local media_version; media_version="$(get_media_mq_version)"
    narrate "Media version: ${media_version:-unknown}"
    if [[ "$(would_be_real_downgrade "$old_version" "$media_version")" == "yes" ]]; then
        warn "ATTENTION: The installed IBM MQ packages (version $old_version) are NEWER than this"
        warn "media (version $media_version). IBM MQ does NOT support a downgrade to a lower"
        warn "version/release/modification level - the IBM package installation script itself"
        warn "refuses this, regardless of apt/rpm options. Forcing it is NOT possible."
        die "Aborted: a real downgrade ($old_version -> $media_version) is not supported by IBM MQ. Please use installation media with version >= $old_version for 'upgrade'."
    fi

    local qms; qms="$(get_all_qm_names)"
    local qms_line="none"
    if [[ -n "$qms" ]]; then
        qms_line="$(echo "$qms" | tr '\n' ' ')"
        narrate "Affected queue managers on this host (will be stopped during the upgrade): $qms_line"
    else
        narrate "No existing queue managers found."
    fi

    narrate "ATTENTION: An upgrade of the version/release/modification (VRM) is NOT reversible once a queue manager has been started with the new code. All queue managers and the Web Console are stopped for the duration of the upgrade (downtime!)."
    local confirm_prompt
    confirm_prompt="Current version: ${old_version:-unknown}  ->  media version: ${media_version:-unknown}
Affected queue managers: ${qms_line}

ATTENTION: A VRM upgrade is NOT reversible once a queue manager has been
started with the new code. All queue managers and the Web Console
are stopped for the duration of the upgrade (downtime!).

Perform the upgrade now?"
    if [[ "$(ask_yes_no "$confirm_prompt" 'no')" != "yes" ]]; then
        cancel_to_menu "Aborted by user (upgrade not confirmed)."
    fi

    if [[ "$(ask_yes_no 'Back up /var/mqm before the upgrade (strongly recommended)?' "$UPGRADE_BACKUP")" == "yes" ]]; then
        narrate "Backing up /var/mqm to ${UPGRADE_BACKUP_DIR}.tar.gz ..."
        run_with_progress "Backing up /var/mqm ..." tar -czf "${UPGRADE_BACKUP_DIR}.tar.gz" -C / var/mqm \
            && info "Backup created: ${UPGRADE_BACKUP_DIR}.tar.gz" \
            || warn "Backup failed – please back up manually before continuing."
    fi

    # Stop mqweb if active
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ibmmq-web.service 2>/dev/null; then
        narrate "Stopping the mqweb systemd service ..."
        systemctl stop ibmmq-web.service || true
    fi
    [[ -x "$MQ_INSTALL_PATH/bin/endmqweb" ]] && su -s /bin/bash mqm -c "'$MQ_INSTALL_PATH/bin/endmqweb'" >>"$LOGFILE" 2>&1 || true

    # Stop all queue managers
    local qm
    for qm in $qms; do
        narrate "Stopping queue manager '$qm' ..."
        su -s /bin/bash mqm -c "endmqm -w '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "'$qm' could not be stopped cleanly (possibly already stopped)."
    done

    accept_license
    ui_menu_intro "Upgrading IBM MQ packages ($PKG_FORMAT)"
    case "$PKG_FORMAT" in
        rpm) upgrade_rpm_packages ;;
        deb) upgrade_deb_packages ;;
    esac
    post_install_setup
    info "New version: ${MQ_INSTALLED_VERSION:-unknown} (before: ${old_version:-unknown})"

    # Start the queue managers again (triggers automatic migration if needed)
    for qm in $qms; do
        info "Starting queue manager '$qm' (migration happens automatically if the VRM level has increased) ..."
        su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "'$qm' could not be started – please check manually (dspmq, AMQERR01.LOG)."
    done

    if [[ -x "$MQ_INSTALL_PATH/bin/strmqweb" ]]; then
        info "Starting the mqweb service again (if configured) ..."
        "$MQ_INSTALL_PATH/bin/strmqweb" >>"$LOGFILE" 2>&1 \
            || warn "mqweb start skipped/failed (possibly not configured)."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 UPGRADE COMPLETED
================================================================================
 Previous version  : ${old_version:-unknown}
 New version       : ${MQ_INSTALLED_VERSION:-unknown}
 Queue managers    : $(echo "$qms" | tr '\n' ' ')
 Backup            : $( [[ -f "${UPGRADE_BACKUP_DIR}.tar.gz" ]] && echo "${UPGRADE_BACKUP_DIR}.tar.gz" || echo "no backup created" )
 Logfile           : $LOGFILE

 IMPORTANT: Check all queue managers (dspmq, AMQERR01.LOG) and applications after the
 upgrade. Rolling back to the old VRM version is NO LONGER
 possible once a queue manager has been started with the new code.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5g) Add an add-on feature to an existing installation (e.g. MQTT/Telemetry, AMS)
#-------------------------------------------------------------------------------
perform_feature_install() {
    echo
    narrate "==== Add an add-on feature to an existing installation ===="
    [[ -n "$MEDIA" ]] || { usage; die "--media is required (mode: feature installation)."; }
    [[ -e "$MEDIA" ]] || die "Media path does not exist: $MEDIA"

    source_mqenv 2>/dev/null || true

    local have_mqtt="no" have_ams="no"
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        rpm -q MQSeriesXRService >/dev/null 2>&1 && have_mqtt="yes"
        rpm -q MQSeriesAMS       >/dev/null 2>&1 && have_ams="yes"
    else
        dpkg -s ibmmq-xrservice >/dev/null 2>&1 && have_mqtt="yes"
        dpkg -s ibmmq-ams       >/dev/null 2>&1 && have_ams="yes"
    fi
    narrate "Current state: MQTT/Telemetry=$have_mqtt  AMS=$have_ams"

    local want_mqtt="$FEATURE_MQTT" want_ams="$FEATURE_AMS"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local sel
            sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Install add-on feature" \
                --checklist "Already installed: MQTT=$have_mqtt  AMS=$have_ams\nSelect what should be installed:" \
                "$rows" "$cols" 2 --separate-output \
                "MQTT" "MQTT/Telemetry (MQSeriesXRService) - connect MQTT clients" "$( [[ "$have_mqtt" == "yes" ]] && echo on || echo off )" \
                "AMS"  "Advanced Message Security (message encryption/signing)" "$( [[ "$have_ams" == "yes" ]] && echo on || echo off )" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
            want_mqtt="no"; want_ams="no"
            local tag
            while IFS= read -r tag; do
                case "$tag" in
                    MQTT) want_mqtt="yes" ;;
                    AMS)  want_ams="yes" ;;
                esac
            done <<< "$sel"
        else
            want_mqtt="$(ask_yes_no 'Install MQTT/Telemetry (MQSeriesXRService)?' "$( [[ "$have_mqtt" == "yes" ]] && echo yes || echo no )")"
            want_ams="$(ask_yes_no  'Install Advanced Message Security (AMS)?'   "$( [[ "$have_ams"  == "yes" ]] && echo yes || echo no )")"
        fi
    fi

    if [[ "$want_mqtt" != "yes" && "$want_ams" != "yes" ]]; then
        info "Nothing selected – nothing to do."
        return 0
    fi

    prepare_media
    accept_license

    local files=() f
    if [[ "$want_mqtt" == "yes" && "$have_mqtt" != "yes" ]]; then
        if [[ "$PKG_FORMAT" == "rpm" ]]; then
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'MQSeriesXRService-*.rpm' | head -n1 || true)"
        else
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'ibmmq-xrservice_*.deb' | head -n1 || true)"
        fi
        if [[ -n "$f" ]]; then files+=("$f"); else warn "MQTT/Telemetry package not found in the media."; fi
    fi
    if [[ "$want_ams" == "yes" && "$have_ams" != "yes" ]]; then
        if [[ "$PKG_FORMAT" == "rpm" ]]; then
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'MQSeriesAMS-*.rpm' | head -n1 || true)"
        else
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'ibmmq-ams_*.deb' | head -n1 || true)"
        fi
        if [[ -n "$f" ]]; then files+=("$f"); else warn "AMS package not found in the media."; fi
    fi

    if [[ ${#files[@]} -gt 0 ]]; then
        narrate "Installing ${#files[@]} additional package(s) ..."
        if [[ "$PKG_FORMAT" == "rpm" ]]; then
            run_with_progress "Installing ${#files[@]} additional package(s) ..." \
                rpm -ivh "${files[@]}" || die "Installation of the additional packages failed. Check logfile: $LOGFILE"
        else
            export DEBIAN_FRONTEND=noninteractive
            run_with_progress "Installing ${#files[@]} additional package(s) ..." \
                apt-get -y install "${files[@]}" || die "Installation of the additional packages failed. Check logfile: $LOGFILE"
        fi
        info "Additional packages installed."
    else
        info "No new packages to install (already present or not selected)."
    fi

    # ---- Enable MQTT/Telemetry on a queue manager ----
    if [[ "$want_mqtt" == "yes" ]]; then
        local target_qm="$MQTT_QM"
        local all_qms; all_qms="$(get_all_qm_names)"
        if [[ -z "$target_qm" ]]; then
            if [[ -z "$all_qms" ]]; then
                warn "No queue managers found – the MQTT service cannot be enabled. Please set it up manually later."
            else
                narrate "Existing queue managers: $(echo "$all_qms" | tr '\n' ' ')"
                target_qm="$(ask "For which queue manager should MQTT/Telemetry be enabled? (existing: $(echo "$all_qms" | tr '\n' ' '))" "$(echo "$all_qms" | head -n1)")"
            fi
        fi
        if [[ -n "$target_qm" ]]; then
            local mqxr_sample="$MQ_INSTALL_PATH/mqxr/samples/installMQXRService_unix.mqsc"
            if [[ -f "$mqxr_sample" ]]; then
                narrate "Setting up SYSTEM.MQXR.SERVICE on '$target_qm' (official IBM sample MQSC) ..."
                cat "$mqxr_sample" | su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                    || warn "Setting up the MQXR service failed – please check the logfile."
                if [[ "$(ask_yes_no 'Create SYSTEM.MQTT.TRANSMIT.QUEUE and set it as the default transmission queue?' "$MQTT_SET_DEFXMITQ")" == "yes" ]]; then
                    su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 <<EOSC || warn "Transmission queue configuration failed."
DEFINE QLOCAL('SYSTEM.MQTT.TRANSMIT.QUEUE') USAGE(XMITQ) MAXDEPTH(100000) REPLACE
ALTER QMGR DEFXMITQ('SYSTEM.MQTT.TRANSMIT.QUEUE')
EOSC
                fi
                su -s /bin/bash mqm -c "echo 'START SERVICE(SYSTEM.MQXR.SERVICE)' | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                    || warn "Starting SYSTEM.MQXR.SERVICE failed (possibly already running or QM not active)."
                info "MQTT/Telemetry set up for '$target_qm'."
                info "Check listener port/TLS with: echo \"DISPLAY SERVICE(SYSTEM.MQXR.SERVICE) ALL\" | runmqsc $target_qm"
            else
                warn "Sample MQSC for the telemetry service not found at: $mqxr_sample"
                warn "Please set up MQTT/Telemetry manually according to the IBM documentation."
            fi
        fi
    fi

    if [[ "$want_ams" == "yes" ]]; then
        info "AMS package processed. Note: AMS protection policies must be defined separately per queue"
        info "(see the IBM documentation on 'AMS policies', setmqspl command)."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 ADD-ON FEATURE(S) PROCESSED
================================================================================
 MQTT/Telemetry : $want_mqtt
 AMS            : $want_ams
 Logfile        : $LOGFILE
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5h) Back up one or all queue managers
#-------------------------------------------------------------------------------
perform_backup() {
    echo
    narrate "==== Back up queue manager(s) ===="

    source_mqenv 2>/dev/null || true

    local all_qms; all_qms="$(get_all_qm_names)"
    if [[ -z "$all_qms" ]]; then
        warn "No queue managers found on this host – no backup possible."
        return 0
    fi

    # ---- Select the queue managers to back up ----
    local -a all_arr=() selected_qms=()
    while IFS= read -r q; do [[ -n "$q" ]] && all_arr+=("$q"); done <<< "$all_qms"

    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        if [[ -z "$BACKUP_QMS" || "$BACKUP_QMS" == "all" ]]; then
            selected_qms=("${all_arr[@]}")
        else
            IFS=',' read -r -a selected_qms <<< "$BACKUP_QMS"
        fi
    elif [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() qm
        for qm in "${all_arr[@]}"; do
            items+=("$qm" "" "on")
        done
        local sel
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Select backup" \
            --checklist "Which queue managers should be backed up?" "$rows" "$cols" "${#all_arr[@]}" \
            --separate-output "${items[@]}" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        while IFS= read -r qm; do
            [[ -n "$qm" ]] && selected_qms+=("$qm")
        done <<< "$sel"
    else
        info "Existing queue managers:"
        local i=0
        for qm in "${all_arr[@]}"; do
            i=$((i+1))
            echo "  $i) $qm"
        done
        local choice
        read -r -p "Choice (numbers comma-separated or 'a' for all) [a]: " choice < /dev/tty || true
        choice="${choice:-a}"
        if [[ "${choice,,}" == "a" ]]; then
            selected_qms=("${all_arr[@]}")
        else
            local -a idxs=(); local idx
            IFS=',' read -r -a idxs <<< "$choice"
            for idx in "${idxs[@]}"; do
                idx="$(echo "$idx" | tr -d '[:space:]')"
                if [[ "$idx" =~ ^[0-9]+$ ]] && [[ "$idx" -ge 1 && "$idx" -le "${#all_arr[@]}" ]]; then
                    selected_qms+=("${all_arr[$((idx-1))]}")
                fi
            done
        fi
    fi

    if [[ ${#selected_qms[@]} -eq 0 ]]; then
        warn "No queue managers selected – backup aborted."
        return 0
    fi
    narrate "Selected for backup: ${selected_qms[*]}"

    local stop_qm="$BACKUP_STOP_QM"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        stop_qm="$(ask_yes_no 'Stop the queue manager during the backup (consistent data backup, recommended)?' "$BACKUP_STOP_QM")"
    fi

    mkdir -p "$BACKUP_DIR" 2>/dev/null || die "Backup directory '$BACKUP_DIR' could not be created."
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local qm cfg_file data_file was_running

    for qm in "${selected_qms[@]}"; do
        echo
        info "---- Backup of queue manager '$qm' ----"
        cfg_file="$BACKUP_DIR/${qm}-config-${ts}.mqsc"
        data_file="$BACKUP_DIR/${qm}-data-${ts}.tar.gz"

        # 1) Configuration export (dmpmqcfg) - also works with an active QM without downtime
        info "Exporting configuration (dmpmqcfg) to $cfg_file ..."
        su -s /bin/bash mqm -c "dmpmqcfg -m '$qm' -x all -a" > "$cfg_file" 2>>"$LOGFILE" \
            || warn "Configuration export for '$qm' failed (queue manager possibly not running)."

        # 2) Optional: stop the QM for a consistent data/log backup
        was_running="no"
        if [[ "$stop_qm" == "yes" ]]; then
            if su -s /bin/bash mqm -c "dspmq -m '$qm'" 2>/dev/null | grep -q "STATUS(Running)"; then
                was_running="yes"
                info "Stopping '$qm' for a consistent data backup ..."
                su -s /bin/bash mqm -c "endmqm -w '$qm'" >>"$LOGFILE" 2>&1 \
                    || warn "'$qm' could not be stopped cleanly – the backup is done anyway."
            fi
        else
            warn "'$qm' stays active during the data backup – the archive may be inconsistent."
        fi

        # 3) Back up the data/log directories
        info "Backing up data/log directories to $data_file ..."
        tar -czf "$data_file" -C / "var/mqm/qmgrs/${qm}" "var/mqm/log/${qm}" >>"$LOGFILE" 2>&1 \
            || warn "Backing up the data/log directories for '$qm' failed."

        # 4) Start the QM again if needed
        if [[ "$was_running" == "yes" ]]; then
            info "Starting '$qm' again ..."
            su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1 \
                || warn "'$qm' could not be started again – please check manually."
        fi

        info "Backup of '$qm' completed: $cfg_file / $data_file"
    done

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 BACKUP COMPLETED
================================================================================
 Queue managers     : ${selected_qms[*]}
 Backup directory   : $BACKUP_DIR
 Timestamp          : $ts
 Logfile            : $LOGFILE

 Note:
   - The configuration (*-config-*.mqsc) can be replayed at any time via
     'runmqsc <QM> < file.mqsc' onto a (new) queue manager.
   - The data/log archive (*-data-*.tar.gz) contains the queue contents
     and must be extracted into /var/mqm/qmgrs and /var/mqm/log for a restore,
     while the target queue manager is stopped.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5i) Restore a queue manager from a backup
#-------------------------------------------------------------------------------
perform_restore() {
    echo
    narrate "==== Restore a queue manager from a backup ===="

    # ---- Choose the source directory with the backup files ----
    local src_dir="${RESTORE_SRC_DIR:-$BACKUP_DIR}"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        src_dir="$(ask 'Source directory with the backup files (*-config-*.mqsc / *-data-*.tar.gz)' "$src_dir")"
    fi
    [[ -d "$src_dir" ]] || die "Directory '$src_dir' does not exist."

    local -a cfg_files=()
    while IFS= read -r f; do [[ -n "$f" ]] && cfg_files+=("$f"); done \
        < <(find "$src_dir" -maxdepth 1 -name '*-config-*.mqsc' 2>/dev/null | sort)
    [[ ${#cfg_files[@]} -gt 0 ]] || die "No backup files (*-config-*.mqsc) found in '$src_dir'."

    # ---- Which backup should be restored? ----
    local chosen_cfg=""
    if [[ -n "$RESTORE_QM" ]]; then
        if [[ -n "$RESTORE_TS" ]]; then
            chosen_cfg="$src_dir/${RESTORE_QM}-config-${RESTORE_TS}.mqsc"
            [[ -f "$chosen_cfg" ]] || die "Backup file not found: $chosen_cfg"
        else
            # Choose the newest backup for this QM name
            chosen_cfg="$(find "$src_dir" -maxdepth 1 -name "${RESTORE_QM}-config-*.mqsc" 2>/dev/null | sort | tail -n1)"
            [[ -n "$chosen_cfg" ]] || die "No backup for QM '$RESTORE_QM' found in '$src_dir'."
        fi
    elif [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Without specification: use the newest existing backup overall
        chosen_cfg="${cfg_files[-1]}"
    elif [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() i=1 f
        for f in "${cfg_files[@]}"; do
            items+=("$i" "$(basename "$f")")
            i=$((i+1))
        done
        local idx
        idx="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Select backup" \
            --menu "Which backup should be restored?" "$rows" "$cols" "${#cfg_files[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        chosen_cfg="${cfg_files[$((idx-1))]}"
    else
        info "Available backups in '$src_dir':"
        local i=1 f
        for f in "${cfg_files[@]}"; do
            echo "  $i) $(basename "$f")"
            i=$((i+1))
        done
        local choice
        read -r -p "Choice [${#cfg_files[@]}]: " choice < /dev/tty || true
        choice="${choice:-${#cfg_files[@]}}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#cfg_files[@]}" ]] || choice="${#cfg_files[@]}"
        chosen_cfg="${cfg_files[$((choice-1))]}"
    fi

    # ---- Derive the QM name and timestamp from the file name: <QM>-config-<TS>.mqsc ----
    local base; base="$(basename "$chosen_cfg" .mqsc)"
    local qm="${base%-config-*}"
    local ts="${base##*-config-}"
    local data_file="$src_dir/${qm}-data-${ts}.tar.gz"
    narrate "Selected backup: queue manager='$qm'  timestamp='$ts'"
    narrate "Configuration file: $chosen_cfg"
    local restore_hint=""
    if [[ -f "$data_file" ]]; then
        narrate "Matching data archive found: $data_file"
    else
        warn "No matching data archive found (expected: $data_file) – only a configuration restore is possible."
        restore_hint=$'\n\nNote: No data archive found - "full" is not available for this backup.'
    fi

    # ---- Choose the restore type ----
    local restore_mode="$RESTORE_MODE"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            restore_mode="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Restore type" \
                --menu "Restore queue manager '$qm' (timestamp $ts):${restore_hint}" "$rows" "$cols" 2 \
                "config" "Configuration only (MQSC re-import, safe, possible live)" \
                "full"   "Complete (restore data/log archive, overwrites data)" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        else
            echo "  1) config - Configuration only (MQSC re-import, safe, possible live)"
            echo "  2) full   - Complete (restore data/log archive, overwrites data)"
            local rchoice
            read -r -p "Restore type [1]: " rchoice < /dev/tty || true
            case "${rchoice:-1}" in
                2) restore_mode="full" ;;
                *) restore_mode="config" ;;
            esac
        fi
    fi

    source_mqenv 2>/dev/null || true

    local qm_exists="no"
    su -s /bin/bash mqm -c "dspmq" 2>/dev/null | grep -q "QMNAME($qm)" && qm_exists="yes" || true

    if [[ "$restore_mode" == "full" ]]; then
        [[ -f "$data_file" ]] || die "No data archive found for a complete restore: $data_file"
        narrate "ATTENTION: A complete restore OVERWRITES all current data of '$qm' irreversibly!"
        if [[ "$(ask_yes_no "ATTENTION: Overwrites all current data of '$qm' irreversibly!\n\nReally restore '$qm' completely from the backup of $ts?" 'no')" != "yes" ]]; then
            cancel_to_menu "Aborted by user (restore not confirmed)."
        fi

        if [[ "$qm_exists" == "yes" ]]; then
            info "Stopping '$qm' ..."
            su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 \
                || warn "'$qm' could not be stopped cleanly (possibly already stopped)."
            info "Removing the current data/log directories of '$qm' ..."
            rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
                || warn "Deleting the old directories partially failed."
        else
            info "Queue manager '$qm' does not exist yet – creating it empty first (for mqs.ini registration) ..."
            su -s /bin/bash mqm -c "crtmqm '$qm'" >>"$LOGFILE" 2>&1 || die "crtmqm for '$qm' failed."
            su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 || true
            rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" || true
        fi

        info "Extracting data archive to /var/mqm ..."
        tar -xzf "$data_file" -C / >>"$LOGFILE" 2>&1 || die "Extracting the data archive failed."
        chown -R mqm:mqm "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
            || warn "chown to 'mqm' failed – please check the permissions."

        info "Starting '$qm' ..."
        start_qmgr_robust "$qm"
        info "Complete restore of '$qm' finished."
    else
        if [[ "$qm_exists" != "yes" ]]; then
            info "Queue manager '$qm' does not exist – creating it fresh ..."
            su -s /bin/bash mqm -c "crtmqm '$qm'" >>"$LOGFILE" 2>&1 || die "crtmqm for '$qm' failed."
            start_qmgr_robust "$qm"
        fi
        info "Replaying configuration from '$chosen_cfg' (runmqsc) ..."
        cat "$chosen_cfg" | su -s /bin/bash mqm -c "runmqsc '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "Replaying the configuration reported errors/warnings – check the logfile."
        info "Configuration restore for '$qm' finished."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 RESTORE COMPLETED
================================================================================
 Queue manager   : $qm
 Restore type    : $restore_mode
 Source          : $chosen_cfg$( [[ "$restore_mode" == "full" ]] && echo ", $data_file" )
 Logfile         : $LOGFILE

 Please check the queue manager: dspmq, AMQERR01.LOG, test the applications.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5j) Completely remove the IBM MQ installation (uninstall)
#-------------------------------------------------------------------------------
perform_uninstall() {
    echo
    narrate "==== Completely remove the IBM MQ installation ===="

    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    local qms_line="none"
    [[ -n "$qms" ]] && qms_line="$(echo "$qms" | tr '\n' ' ')"

    local pkg_list=""
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        pkg_list="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep '^MQSeries' || true)"
    else
        pkg_list="$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep '^ibmmq-' || true)"
    fi

    narrate "ATTENTION: This action IRREVERSIBLY removes:"
    narrate "  - All queue managers on this host including messages/data: $qms_line"
    narrate "  - All IBM MQ packages ($([[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l) packages" || echo "none found"))"
    narrate "  - Associated systemd services and convenience aliases"
    narrate "This action can NOT be undone."

    local confirm_prompt
    confirm_prompt="Affected queue managers: ${qms_line}
Packages found: $( [[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l)" || echo "0" )

ATTENTION: This action deletes ALL queue managers including data and removes
all IBM MQ packages IRREVERSIBLY from this host.

Really remove everything?"
    local proceed="$UNINSTALL_CONFIRM"
    if [[ -z "$proceed" ]]; then
        proceed="$(ask_yes_no "$confirm_prompt" 'no')"
    fi
    if [[ "$proceed" != "yes" ]]; then
        cancel_to_menu "Aborted by user (uninstall not confirmed)."
    fi

    if [[ "$(ask_yes_no 'Create a backup of all queue managers before removal (recommended)?' "$UNINSTALL_BACKUP_FIRST")" == "yes" ]]; then
        info "Creating a backup before uninstalling ..."
        BACKUP_QMS="all"; BACKUP_STOP_QM="yes"
        perform_backup || warn "The backup reported problems - the uninstall continues anyway."
    fi

    local remove_user="$UNINSTALL_REMOVE_USER"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        remove_user="$(ask_yes_no 'Also completely remove the user/group "mqm" and /var/mqm (only sensible if IBM MQ will never be installed on this host again)?' "$UNINSTALL_REMOVE_USER")"
    fi

    # ---- Stop mqweb ----
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ibmmq-web.service 2>/dev/null; then
        info "Stopping the mqweb systemd service ..."
        systemctl disable --now ibmmq-web.service >>"$LOGFILE" 2>&1 || true
    fi
    [[ -x "$MQ_INSTALL_PATH/bin/endmqweb" ]] && su -s /bin/bash mqm -c "'$MQ_INSTALL_PATH/bin/endmqweb'" >>"$LOGFILE" 2>&1 || true

    # ---- Cleanly delete all queue managers ----
    local qm failed_qms=()
    for qm in $qms; do
        info "Removing queue manager '$qm' ..."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now "ibmmq-${qm}.service" >>"$LOGFILE" 2>&1 || true
        fi
        delete_qmgr_robust "$qm" || failed_qms+=("$qm")
    done

    # ---- Clean up systemd unit files ----
    if [[ -d /etc/systemd/system ]]; then
        rm -f /etc/systemd/system/ibmmq-*.service 2>>"$LOGFILE" || true
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    fi

    # ---- Remove convenience aliases ----
    if [[ -f /etc/profile.d/mqm-aliases.sh ]]; then
        info "Removing alias file /etc/profile.d/mqm-aliases.sh ..."
        rm -f /etc/profile.d/mqm-aliases.sh 2>>"$LOGFILE" || warn "Alias file could not be removed."
    fi

    # ---- Remove /etc/profile.d/mqenv.sh ----
    rm -f /etc/profile.d/mqenv.sh 2>>"$LOGFILE" || true

    # ---- Remove packages ----
    info "Removing IBM MQ packages ..."
    local -a pkg_arr=()
    [[ -n "$pkg_list" ]] && mapfile -t pkg_arr <<< "$pkg_list"
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        if [[ -n "$pkg_list" ]]; then
            run_with_progress "Removing $(echo "$pkg_list" | wc -l) RPM package(s) ..." \
                rpm -e "${pkg_arr[@]}" \
                || warn "Some RPM packages could not be removed - check the logfile."
        fi
    else
        export DEBIAN_FRONTEND=noninteractive
        if [[ -n "$pkg_list" ]]; then
            run_with_progress "Removing $(echo "$pkg_list" | wc -l) DEB package(s) ..." \
                apt-get -y purge "${pkg_arr[@]}" \
                || warn "Some DEB packages could not be removed - check the logfile."
            apt-get -y autoremove >>"$LOGFILE" 2>&1 || true
        fi
    fi

    # ---- Optional: completely remove the mqm user/group and /var/mqm ----
    if [[ "$remove_user" == "yes" ]]; then
        warn "Completely removing user 'mqm', group 'mqm' and /var/mqm ..."
        if [[ ${#failed_qms[@]} -gt 0 ]]; then
            warn "Note: the clean deletion failed for the following QM(s), their data will now"
            warn "be removed together with /var/mqm anyway: ${failed_qms[*]}"
        fi
        id mqm >/dev/null 2>&1 && userdel -r mqm >>"$LOGFILE" 2>&1
        getent group mqm >/dev/null 2>&1 && groupdel mqm >>"$LOGFILE" 2>&1 || true
        rm -rf /var/mqm 2>>"$LOGFILE" || warn "/var/mqm could not be removed completely."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 UNINSTALL COMPLETED
================================================================================
 Removed queue managers  : ${qms_line}
$( [[ ${#failed_qms[@]} -gt 0 ]] && echo " Not removed cleanly (only directories deleted): ${failed_qms[*]}" )
 Removed packages        : $( [[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l)" || echo "0" )
 mqm user/group, /var/mqm: $( [[ "$remove_user" == "yes" ]] && echo "removed" || echo "kept" )
 Logfile                 : $LOGFILE

 Note: '$MQ_INSTALL_PATH' (installation directory) is usually removed
 automatically by the package managers. If remnants remain, check manually.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5k) Create objects for an existing queue manager (channels, listeners)
#-------------------------------------------------------------------------------
perform_create_objects() {
    echo
    narrate "==== Create objects for a queue manager ===="
    if ! id mqm >/dev/null 2>&1; then
        die "User 'mqm' does not exist - IBM MQ does not seem to be installed on this host."
    fi
    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    [[ -n "$qms" ]] || die "No queue managers found on this host."
    local -a all_arr=()
    while IFS= read -r q; do [[ -n "$q" ]] && all_arr+=("$q"); done <<< "$qms"

    # ---- Select queue manager ----
    local target_qm=""
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() qm
        for qm in "${all_arr[@]}"; do items+=("$qm" ""); done
        target_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Select queue manager" \
            --menu "For which queue manager should objects be created?" "$rows" "$cols" "${#all_arr[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
    else
        info "Existing queue managers:"
        local i=0
        for qm in "${all_arr[@]}"; do i=$((i+1)); echo "  $i) $qm"; done
        local choice
        read -r -p "Choice [1]: " choice < /dev/tty || true
        choice="${choice:-1}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#all_arr[@]}" ]] || choice=1
        target_qm="${all_arr[$((choice-1))]}"
    fi
    [[ -n "$target_qm" ]] || cancel_to_menu "No queue manager selected."

    # ---- Which objects should be created? ----
    local -a to_create=()
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Objects for $target_qm" \
            --checklist "What should be created?" "$rows" "$cols" 2 --separate-output \
            "CHANNEL"  "Connection channel for MQ Explorer/client (SVRCONN)" on \
            "LISTENER" "Additional TCP listener (new port)" off \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
        local tag
        while IFS= read -r tag; do to_create+=("$tag"); done <<< "$sel"
    else
        local want_c want_l
        want_c="$(ask_yes_no 'Create a connection channel (SVRCONN) for MQ Explorer/client?' 'yes')"
        want_l="$(ask_yes_no 'Create an additional TCP listener?' 'no')"
        [[ "$want_c" == "yes" ]] && to_create+=("CHANNEL")
        [[ "$want_l" == "yes" ]] && to_create+=("LISTENER")
    fi
    if [[ ${#to_create[@]} -eq 0 ]]; then
        info "Nothing selected - nothing to do."
        return 0
    fi

    # ---- Ask for details and prepare MQSC ----
    local mqsc_file; mqsc_file="$(mktemp /tmp/objects.XXXXXX.mqsc)"
    : > "$mqsc_file"
    local summary="" cname="" cuser="" lname="" lport=""

    local item
    for item in "${to_create[@]}"; do
        case "$item" in
            CHANNEL)
                cname="$(ask 'Name of the new channel (SVRCONN)' 'EXPLORER.SVRCONN')"
                cuser="$(ask 'MCAUSER (non-privileged application user)' "${MQ_APP_USER:-mqapp}")"
                local ctls; ctls="$(ask_yes_no 'Require TLS for this channel?' 'no')"
                {
                    echo "* Dedicated channel with a fixed, non-privileged MCAUSER (IBM best practice:"
                    echo "* never use SYSTEM.DEF.SVRCONN for applications/MQ Explorer)"
                    if [[ "$ctls" == "yes" ]]; then
                        echo "DEFINE CHANNEL('$cname') CHLTYPE(SVRCONN) MCAUSER('$cuser') +"
                        echo "       SSLCIPH('${TLS_CIPHER:-ANY_TLS12_OR_HIGHER}') SSLCAUTH(OPTIONAL) REPLACE"
                    else
                        echo "DEFINE CHANNEL('$cname') CHLTYPE(SVRCONN) MCAUSER('$cuser') REPLACE"
                    fi
                    echo "SET CHLAUTH('$cname') TYPE(ADDRESSMAP) ADDRESS('*') +"
                    echo "    USERSRC(CHANNEL) CHCKCLNT(REQUIRED) +"
                    echo "    DESCR('Additional application access') ACTION(REPLACE)"
                } >> "$mqsc_file"
                summary+="  Channel '$cname' (MCAUSER: $cuser, TLS: $ctls)"$'\n'
                ;;
            LISTENER)
                lname="$(ask 'Name of the new listener' 'LISTENER.TCP2')"
                lport="$(ask 'Port of the new listener' '1415')"
                {
                    echo "* Additional, dedicated TCP listener"
                    echo "DEFINE LISTENER('$lname') TRPTYPE(TCP) PORT($lport) CONTROL(QMGR) REPLACE"
                    echo "START LISTENER('$lname')"
                } >> "$mqsc_file"
                summary+="  Listener '$lname' on port $lport"$'\n'
                ;;
        esac
    done

    info "Applying MQSC to '$target_qm' ..."
    cat "$mqsc_file" | su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
        || die "Applying the MQSC to '$target_qm' failed. Check logfile: $LOGFILE"
    rm -f "$mqsc_file"

    # Least privilege via the shared permission group (not per
    # user): add the MCAUSER of the new channel to the group and grant the
    # group (idempotent, harmless when called again) QMGR connect/
    # inq for this QM.
    if [[ -n "$cuser" ]]; then
        getent group "$MQ_APP_GROUP" >/dev/null || groupadd "$MQ_APP_GROUP"
        if id "$cuser" >/dev/null 2>&1; then
            if ! id -nG "$cuser" | grep -qw "$MQ_APP_GROUP"; then
                usermod -aG "$MQ_APP_GROUP" "$cuser"
                info "'$cuser' added to the permission group '$MQ_APP_GROUP'."
            fi
        else
            warn "OS user '$cuser' does not exist - group assignment skipped (only MCAUSER set in MQSC)."
        fi
        su -s /bin/bash mqm -c "setmqaut -m '$target_qm' -t qmgr -g '$MQ_APP_GROUP' +connect +inq" >>"$LOGFILE" 2>&1 \
            || warn "setmqaut (group '$MQ_APP_GROUP') for '$target_qm' failed - please check manually."
    fi

    # Open the firewall port for a new listener (optional)
    if [[ -n "$lport" ]]; then
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
            if [[ "$(ask_yes_no "Open port $lport/tcp in firewalld?" 'yes')" == "yes" ]]; then
                firewall-cmd --permanent --add-port="${lport}/tcp" >>"$LOGFILE" 2>&1 || true
                firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            fi
        elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
            if [[ "$(ask_yes_no "Open port $lport/tcp in ufw?" 'yes')" == "yes" ]]; then
                ufw allow "${lport}/tcp" >>"$LOGFILE" 2>&1 || true
            fi
        fi
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 OBJECTS CREATED FOR '$target_qm'
================================================================================
$summary
EOF

    if [[ -n "$cname" ]]; then
        local host_fqdn; host_fqdn="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo '<host>')"
        local host_ips; host_ips="$(hostname -I 2>/dev/null | tr -s ' ' | sed 's/ *$//')"
        cat <<EOF | tee -a "$LOGFILE"
 MQ EXPLORER CONNECTION PARAMETERS:
   Queue manager name .......... : $target_qm
   Host name or IP address ..... : $host_fqdn   (or: ${host_ips:-<ip-address>})
   Server-connection channel ... : $cname
   User ID ...................... : $cuser  (+ its OS password, if CONNAUTH is active)
   Permission group ............. : $MQ_APP_GROUP (setmqaut rights are granted to this group)
================================================================================
EOF
    fi
}

#-------------------------------------------------------------------------------
# 5l) SSL/TLS management (self-signed and "real" CA certificates)
#-------------------------------------------------------------------------------
# Asks whether an own password should be set for a new key repository or
# one should be generated automatically. Outputs the chosen password.
# ask_secret() already handles confirmation/empty check/repetition itself.
choose_keydb_password() {
    local use_own
    use_own="$(ask_yes_no 'Set your own password for the key repository (instead of an auto-generated one)?' 'no')"
    if [[ "$use_own" == "yes" ]]; then
        ask_secret 'Password for the key repository' ''
    else
        openssl rand -base64 18 2>/dev/null || echo "Chg-Me-$(date +%s)"
    fi
}

# Workflow for a "real" CA certificate (IBM best practice, in this
# order): 1) create CSR -> 2) send it to the CA -> 3) add the root/intermediate
# certificates of the CA as "trust" (IMPORTANT: BEFORE step 4, otherwise
# the trust chain check fails) -> 4) "receive" the certificate signed by
# the CA (runmqakm -cert -receive - NOT -cert -add, which
# would not link it with the private key and make it unusable).
# All actions use "-stashed" (no password needed), since the
# key repository is always created with "-stash" (also
# with a self-chosen password - the stash file allows later
# commands access without entering the password again each time;
# the password nevertheless remains valid and can be used e.g. in iKeyman).
perform_tls_management() {
    echo
    narrate "==== SSL/TLS management ===="
    if ! id mqm >/dev/null 2>&1; then
        die "User 'mqm' does not exist - IBM MQ does not seem to be installed on this host."
    fi
    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    [[ -n "$qms" ]] || die "No queue managers found on this host."
    local -a all_arr=()
    while IFS= read -r q; do [[ -n "$q" ]] && all_arr+=("$q"); done <<< "$qms"

    # ---- Select queue manager ----
    local target_qm=""
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() qm
        for qm in "${all_arr[@]}"; do items+=("$qm" ""); done
        target_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Select queue manager" \
            --menu "For which queue manager should SSL/TLS be managed?" "$rows" "$cols" "${#all_arr[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
    else
        info "Existing queue managers:"
        local i=0
        for qm in "${all_arr[@]}"; do i=$((i+1)); echo "  $i) $qm"; done
        local choice
        read -r -p "Choice [1]: " choice < /dev/tty || true
        choice="${choice:-1}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#all_arr[@]}" ]] || choice=1
        target_qm="${all_arr[$((choice-1))]}"
    fi
    [[ -n "$target_qm" ]] || cancel_to_menu "No queue manager selected."

    local ssldir="/var/mqm/qmgrs/${target_qm}/ssl"
    local keydb="${ssldir}/key"
    local kdb_file="${keydb}.kdb"
    su -s /bin/bash mqm -c "mkdir -p '$ssldir'" >>"$LOGFILE" 2>&1 || true
    local kdb_exists="no"; [[ -f "$kdb_file" ]] && kdb_exists="yes"

    # ---- Select action ----
    local action="SELFSIGNED"
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        action="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "SSL/TLS for $target_qm (repository: $( [[ "$kdb_exists" == "yes" ]] && echo present || echo "not yet created" ))" \
            --menu "What would you like to do?" "$rows" "$cols" 7 \
            "SELFSIGNED" "Create/renew a self-signed certificate (quick start, test)" \
            "CSR"        "Create a CSR for a real CA (best practice, production)" \
            "TRUST"      "Add a CA root/intermediate certificate as trusted" \
            "RECEIVE"    "Import the certificate signed by the CA" \
            "LIST"       "Show the certificates in the repository" \
            "DETAILS"    "Show details/expiry date of a certificate" \
            "PASSWORD"   "Change the password of the key repository" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted by user."
    else
        echo "Key repository for '$target_qm': $( [[ "$kdb_exists" == "yes" ]] && echo "present ($kdb_file)" || echo "not yet created" )"
        echo "  1) Create/renew a self-signed certificate (quick start, test)"
        echo "  2) Create a CSR for a real CA (best practice, production)"
        echo "  3) Add a CA root/intermediate certificate as trusted"
        echo "  4) Import the certificate signed by the CA"
        echo "  5) Show the certificates in the repository"
        echo "  6) Show details/expiry date of a certificate"
        echo "  7) Change the password of the key repository"
        local achoice
        read -r -p "Choice [1]: " achoice < /dev/tty || true
        case "${achoice:-1}" in
            2) action="CSR" ;;
            3) action="TRUST" ;;
            4) action="RECEIVE" ;;
            5) action="LIST" ;;
            6) action="DETAILS" ;;
            7) action="PASSWORD" ;;
            *) action="SELFSIGNED" ;;
        esac
    fi

    case "$action" in
        SELFSIGNED)
            local tls_label; tls_label="$(ask 'Certificate label' "qm.${target_qm,,}")"
            local dn_default="${TLS_CERT_DN#*,}"
            [[ "$dn_default" == "$TLS_CERT_DN" ]] && dn_default="O=Example,C=DE"
            local cert_dn; cert_dn="$(ask 'Distinguished Name (DN)' "CN=${target_qm},${dn_default}")"
            if [[ "$kdb_exists" != "yes" ]]; then
                local tlspw; tlspw="$(choose_keydb_password)"
                su -s /bin/bash mqm -c "runmqakm -keydb -create -db '$kdb_file' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
                    || die "Creating the key repository for '$target_qm' failed."
                info "Key repository for '$target_qm' created: $kdb_file"
            fi
            su -s /bin/bash mqm -c "runmqakm -cert -create -db '$kdb_file' -stashed -label '$tls_label' -dn '$cert_dn' -size 2048 -sig_alg SHA256WithRSA -expire 365" >>"$LOGFILE" 2>&1 \
                || die "Creating the certificate for '$target_qm' failed."
            su -s /bin/bash mqm -c "echo \"ALTER QMGR SSLKEYR('$keydb') CERTLABL('$tls_label')
REFRESH SECURITY TYPE(SSL)\" | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                || warn "ALTER QMGR/REFRESH SECURITY reported problems - please check manually."
            info "Self-signed certificate '$tls_label' for '$target_qm' created and activated (SSLKEYR/CERTLABL set, security cache refreshed)."
            warn "Note: self-signed certificates are suitable for tests. For production IBM recommends"
            warn "a certificate signed by a real CA (see menu item 'Create a CSR')."
            ;;
        CSR)
            if [[ "$kdb_exists" != "yes" ]]; then
                local tlspw; tlspw="$(choose_keydb_password)"
                su -s /bin/bash mqm -c "runmqakm -keydb -create -db '$kdb_file' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
                    || die "Creating the key repository for '$target_qm' failed."
                info "Key repository for '$target_qm' created: $kdb_file"
            fi
            local tls_label; tls_label="$(ask 'Certificate label (will later be set as CERTLABL)' "qm.${target_qm,,}")"
            local dn_default="${TLS_CERT_DN#*,}"
            [[ "$dn_default" == "$TLS_CERT_DN" ]] && dn_default="O=Example,C=DE"
            local cert_dn; cert_dn="$(ask 'Distinguished Name (DN) for the CSR' "CN=${target_qm},${dn_default}")"
            local csr_file="${ssldir}/${target_qm}.csr"
            su -s /bin/bash mqm -c "runmqakm -certreq -create -db '$kdb_file' -stashed -label '$tls_label' -dn '$cert_dn' -size 2048 -sigalg SHA256WithRSA -file '$csr_file'" >>"$LOGFILE" 2>&1 \
                || die "Creating the CSR for '$target_qm' failed."
            chown mqm:mqm "$csr_file" 2>/dev/null || true
            cat <<EOF | tee -a "$LOGFILE"

================================================================================
 CSR CREATED FOR '$target_qm'
================================================================================
 File   : $csr_file
 Label  : $tls_label
 DN     : $cert_dn

 Next steps:
   1. Send this file to your certificate authority (CA).
   2. After receiving it: import the root/intermediate certificates of the CA as trusted
      via the menu item 'Add a CA root/intermediate certificate'
      (IMPORTANT: this step must happen BEFORE step 3).
   3. Then import the actual certificate signed by the CA via
      'Import the certificate signed by the CA' for the same label ('$tls_label').
================================================================================
EOF
            ;;
        TRUST)
            if [[ "$kdb_exists" != "yes" ]]; then
                die "No key repository exists for '$target_qm'. Please choose 'self-signed' or 'CSR' first."
            fi
            local src_file; src_file="$(ask 'Path to the CA certificate file (root or intermediate certificate, PEM/.cer/.crt)' '')"
            [[ -f "$src_file" ]] || die "File not found: $src_file"
            local trust_label; trust_label="$(ask 'Label for this trust certificate' 'ca-root')"
            local dst_file; dst_file="${ssldir}/$(basename "$src_file")"
            cp "$src_file" "$dst_file" && chown mqm:mqm "$dst_file" 2>/dev/null \
                || die "Copying the certificate file to '$ssldir' failed."
            su -s /bin/bash mqm -c "runmqakm -cert -add -db '$kdb_file' -stashed -label '$trust_label' -file '$dst_file' -format ascii" >>"$LOGFILE" 2>&1 \
                || die "Adding the trust certificate '$trust_label' failed."
            info "Trust certificate '$trust_label' added to '$target_qm'."
            ;;
        RECEIVE)
            if [[ "$kdb_exists" != "yes" ]]; then
                die "No key repository exists for '$target_qm'. Please request a certificate via CSR first."
            fi
            local src_file; src_file="$(ask 'Path to the certificate file signed by the CA' '')"
            [[ -f "$src_file" ]] || die "File not found: $src_file"
            local dst_file; dst_file="${ssldir}/$(basename "$src_file")"
            cp "$src_file" "$dst_file" && chown mqm:mqm "$dst_file" 2>/dev/null \
                || die "Copying the certificate file to '$ssldir' failed."
            su -s /bin/bash mqm -c "runmqakm -cert -receive -db '$kdb_file' -stashed -file '$dst_file'" >>"$LOGFILE" 2>&1 \
                || die "Importing the signed certificate failed. Check: have the root/intermediate certificates of the CA already been added as trusted (menu item 'Add a CA root/intermediate certificate')?"
            info "Signed certificate for '$target_qm' imported successfully."
            local tls_label; tls_label="$(ask 'Label of the certificate just received (for CERTLABL)' "qm.${target_qm,,}")"
            su -s /bin/bash mqm -c "echo \"ALTER QMGR SSLKEYR('$keydb') CERTLABL('$tls_label')
REFRESH SECURITY TYPE(SSL)\" | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                || warn "ALTER QMGR/REFRESH SECURITY reported problems - please check manually."
            info "SSLKEYR/CERTLABL set for '$target_qm' and security cache refreshed."
            ;;
        LIST)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "No key repository exists for '$target_qm' (TLS has not been set up for this QM yet)."
                warn "Please choose 'Create/renew a self-signed certificate' or 'Create a CSR for a real CA' first."
            else
                local out; out="$(su -s /bin/bash mqm -c "runmqakm -cert -list -db '$kdb_file' -stashed" 2>&1)" || true
                echo "$out" | tee -a "$LOGFILE"
                if [[ "$UI_MODE" == "tui" ]]; then
                    read -r rows cols <<< "$(ui_dims)"
                    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Certificates in $target_qm" \
                        --msgbox "${out:-No certificates found.}" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
                fi
            fi
            ;;
        DETAILS)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "No key repository exists for '$target_qm' (TLS has not been set up for this QM yet)."
                warn "Please choose 'Create/renew a self-signed certificate' or 'Create a CSR for a real CA' first."
            else
                local label; label="$(ask 'Label of the certificate' "qm.${target_qm,,}")"
                local out; out="$(su -s /bin/bash mqm -c "runmqakm -cert -details -db '$kdb_file' -stashed -label '$label'" 2>&1)" || true
                echo "$out" | tee -a "$LOGFILE"
                if [[ "$UI_MODE" == "tui" ]]; then
                    read -r rows cols <<< "$(ui_dims)"
                    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Certificate details: $label" \
                        --msgbox "${out:-No certificate with this label found.}" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
                fi
            fi
            ;;
        PASSWORD)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "No key repository exists for '$target_qm' (TLS has not been set up for this QM yet)."
                warn "Please choose 'Create/renew a self-signed certificate' or 'Create a CSR for a real CA' first."
            else
                narrate "Note: if the current password was generated automatically and is not known,"
                narrate "it cannot be changed here - in that case create the repository anew instead."
                local old_pw; old_pw="$(ask_secret 'Current password of the key repository' '')"
                local new_pw; new_pw="$(ask_secret 'New password' '')"
                su -s /bin/bash mqm -c "runmqakm -keydb -changepw -db '$kdb_file' -pw '$old_pw' -new_pw '$new_pw' -stash" >>"$LOGFILE" 2>&1 \
                    || die "Changing the password for '$target_qm' failed (wrong current password?). Check logfile: $LOGFILE"
                info "Password of the key repository for '$target_qm' changed (re-stashed, 'CSR'/'self-signed' etc. keep working without entering the password again)."
            fi
            ;;
    esac
}

run_main_flow() {
# Store our own PID (not $$, which in some bash versions still returns the PID
# of the top-level shell inside subshells) for the cancel_to_menu() signal mechanism,
# plus trap: a received USR1 signal ends THIS subshell
# immediately with code 99, regardless of how deep it currently hangs in nested
# command substitutions (e.g. "X=\"\$(ask ...)\"").
RUN_MAIN_FLOW_PID=$BASHPID
trap 'exit 99' USR1
main_menu

# For the modes "install"/"upgrade"/"feature" the installation media is strictly
# required; if it is not (yet) set via --media, it is asked for interactively.
if [[ "$MODE" =~ ^(install|upgrade|feature)$ ]]; then
    ensure_media_path "$MODE"
fi

# Upgrade, feature installation, backup and restore are independent flows
# that do not go through QM creation/provisioning: branch off here and finish.
if [[ "$MODE" == "upgrade" ]]; then
    perform_upgrade
    exit 0
fi
if [[ "$MODE" == "feature" ]]; then
    perform_feature_install
    exit 0
fi
if [[ "$MODE" == "backup" ]]; then
    perform_backup
    return_to_menu
fi
if [[ "$MODE" == "restore" ]]; then
    perform_restore
    return_to_menu
fi
if [[ "$MODE" == "uninstall" ]]; then
    perform_uninstall
    exit 0
fi
if [[ "$MODE" == "objects" ]]; then
    perform_create_objects
    return_to_menu
fi
if [[ "$MODE" == "tls" ]]; then
    perform_tls_management
    return_to_menu
fi

#-------------------------------------------------------------------------------
# 5d) Consolidated selection dialogs for security features and components
#-------------------------------------------------------------------------------
# Whiptail checklists return the selected tags space-separated (our
# tags contain no spaces, so no quoting is to be expected).
select_security_features() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        return 0  # values come unchanged from the environment variables/defaults
    fi

    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        # IMPORTANT: --separate-output returns one tag per line WITHOUT quotes.
        # Without this option whiptail/dialog quotes every tag (e.g. "CONNAUTH"), which
        # the following case comparison would otherwise never match (bug: always "no").
        # The "|| { ...; return 1; }" must be attached directly to the assignment, since a
        # later "if [[ $? -ne 0 ]]" would never be reached under 'set -e'.
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Standard security features" \
            --cancel-button "Back" \
            --checklist "Toggle with SPACE, confirm with ENTER.\n(Cancel = back to the main menu)" "$rows" "$cols" 4 \
            --separate-output \
            "CONNAUTH"  "Connection authentication (enforce user/password)"         "$( [[ "$SEC_CONNAUTH" == "yes" ]] && echo on || echo off )" \
            "CHLAUTH"   "Keep channel authentication records active"               "$( [[ "$SEC_CHLAUTH" == "yes" ]] && echo on || echo off )" \
            "BLOCKPRIV" "Block privileged users on channels"                       "$( [[ "$SEC_BLOCK_PRIV" == "yes" ]] && echo on || echo off )" \
            "TLS"       "Set up TLS (key repository + self-signed certificate)"    "$( [[ "$SEC_TLS" == "yes" ]] && echo on || echo off )" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted (security features)."
        SEC_CONNAUTH="no"; SEC_CHLAUTH="no"; SEC_BLOCK_PRIV="no"; SEC_TLS="no"
        local tag
        while IFS= read -r tag; do
            case "$tag" in
                CONNAUTH)  SEC_CONNAUTH="yes" ;;
                CHLAUTH)   SEC_CHLAUTH="yes" ;;
                BLOCKPRIV) SEC_BLOCK_PRIV="yes" ;;
                TLS)       SEC_TLS="yes" ;;
            esac
        done <<< "$sel"
    else
        # Text fallback: numbered toggle menu instead of individual yes/no questions
        info "==== Standard security features ===="
        while true; do
            echo "  1) [$( [[ "$SEC_CONNAUTH" == "yes" ]] && echo x || echo ' ' )] Connection authentication (enforce user/password)"
            echo "  2) [$( [[ "$SEC_CHLAUTH" == "yes" ]] && echo x || echo ' ' )] Keep channel authentication records active"
            echo "  3) [$( [[ "$SEC_BLOCK_PRIV" == "yes" ]] && echo x || echo ' ' )] Block privileged users on channels"
            echo "  4) [$( [[ "$SEC_TLS" == "yes" ]] && echo x || echo ' ' )] Set up TLS (key repository + self-signed certificate)"
            local sel
            read -r -p "Number to toggle, 'c' continue, 'b' back to the main menu [c]: " sel < /dev/tty || true
            case "${sel:-c}" in
                1) [[ "$SEC_CONNAUTH" == "yes" ]] && SEC_CONNAUTH="no" || SEC_CONNAUTH="yes" ;;
                2) [[ "$SEC_CHLAUTH" == "yes" ]] && SEC_CHLAUTH="no" || SEC_CHLAUTH="yes" ;;
                3) [[ "$SEC_BLOCK_PRIV" == "yes" ]] && SEC_BLOCK_PRIV="no" || SEC_BLOCK_PRIV="yes" ;;
                4) [[ "$SEC_TLS" == "yes" ]] && SEC_TLS="no" || SEC_TLS="yes" ;;
                b|B|z|Z) cancel_to_menu "Aborted (security features)." ;;
                c|C|f|F|"") break ;;
                *) warn "Invalid input." ;;
            esac
        done
    fi
    narrate "Security features: CONNAUTH=$SEC_CONNAUTH CHLAUTH=$SEC_CHLAUTH BLOCKPRIV=$SEC_BLOCK_PRIV TLS=$SEC_TLS"
    return 0
}

select_optional_components() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        return 0  # values come unchanged from the environment variables/defaults
    fi

    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Optional components" \
            --cancel-button "Back" \
            --checklist "Toggle with SPACE, confirm with ENTER.\n(Cancel = back to the main menu)" "$rows" "$cols" 4 \
            --separate-output \
            "AMS"       "Install Advanced Message Security (AMS)"                            "$( [[ "$SEC_AMS" == "yes" ]] && echo on || echo off )" \
            "WEB"       "Install MQ Web Console"                                             "$( [[ "$INST_WEB" == "yes" ]] && echo on || echo off )" \
            "AUTOSTART" "Set up systemd autostart for the queue managers"                    "$( [[ "$ENABLE_AUTOSTART" == "yes" ]] && echo on || echo off )" \
            "ALIASES"   "Create convenience aliases (tail-/mqsc-/status-<qm> etc.)"          "$( [[ "$ENABLE_ALIASES" == "yes" ]] && echo on || echo off )" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Aborted (optional components)."
        SEC_AMS="no"; INST_WEB="no"; ENABLE_AUTOSTART="no"; ENABLE_ALIASES="no"
        local tag
        while IFS= read -r tag; do
            case "$tag" in
                AMS)       SEC_AMS="yes" ;;
                WEB)       INST_WEB="yes" ;;
                AUTOSTART) ENABLE_AUTOSTART="yes" ;;
                ALIASES)   ENABLE_ALIASES="yes" ;;
            esac
        done <<< "$sel"
    else
        info "==== Optional components ===="
        while true; do
            echo "  1) [$( [[ "$SEC_AMS" == "yes" ]] && echo x || echo ' ' )] Install Advanced Message Security (AMS)"
            echo "  2) [$( [[ "$INST_WEB" == "yes" ]] && echo x || echo ' ' )] Install MQ Web Console"
            echo "  3) [$( [[ "$ENABLE_AUTOSTART" == "yes" ]] && echo x || echo ' ' )] Set up systemd autostart for the queue managers"
            echo "  4) [$( [[ "$ENABLE_ALIASES" == "yes" ]] && echo x || echo ' ' )] Create convenience aliases (tail-/mqsc-/status-<qm> etc.)"
            local sel
            read -r -p "Number to toggle, 'c' continue, 'b' back [c]: " sel < /dev/tty || true
            case "${sel:-c}" in
                1) [[ "$SEC_AMS" == "yes" ]] && SEC_AMS="no" || SEC_AMS="yes" ;;
                2) [[ "$INST_WEB" == "yes" ]] && INST_WEB="no" || INST_WEB="yes" ;;
                3) [[ "$ENABLE_AUTOSTART" == "yes" ]] && ENABLE_AUTOSTART="no" || ENABLE_AUTOSTART="yes" ;;
                4) [[ "$ENABLE_ALIASES" == "yes" ]] && ENABLE_ALIASES="no" || ENABLE_ALIASES="yes" ;;
                b|B|z|Z) cancel_to_menu "Aborted (optional components)." ;;
                c|C|f|F|"") break ;;
                *) warn "Invalid input." ;;
            esac
        done
    fi
    narrate "Optional components: AMS=$SEC_AMS WEB=$INST_WEB AUTOSTART=$ENABLE_AUTOSTART ALIASES=$ENABLE_ALIASES"
    return 0
}

#-------------------------------------------------------------------------------
# 6) Interactive parameter prompting
#-------------------------------------------------------------------------------
gather_parameters() {
    echo
    narrate "==== MQ parameters ===="

    # --- Determine the queue managers (1..x) ---
    if [[ -n "$MQ_QMGRS" ]]; then
        # Parse the given specification: NAME:PORT:CHANNEL,...
        parse_qmgr_spec "$MQ_QMGRS"
        narrate "Queue managers taken from MQ_QMGRS (${#QMGR_NAMES[@]} total)."
    elif [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Backward compatible: a single QM from the individual variables
        QMGR_NAMES=("$MQ_QMGR_NAME"); QMGR_PORTS=("$MQ_LISTENER_PORT"); QMGR_CHANNELS=("$MQ_APP_CHANNEL")
    else
        local count
        count="$(ask 'How many queue managers should be created?' '1')"
        [[ "$count" =~ ^[0-9]+$ && "$count" -ge 1 ]] || count=1
        local i name port chan defname defport
        for (( i=1; i<=count; i++ )); do
            echo
            narrate "--- Queue manager $i of $count ---"
            if [[ $i -eq 1 ]]; then defname="$MQ_QMGR_NAME"; defport="$MQ_LISTENER_PORT"
            else defname="QM${i}"; defport=$(( 1413 + i )); fi
            name="$(ask "  Name of QM $i" "$defname")"
            port="$(ask "  Listener port for '$name'" "$defport")"
            chan="$(ask "  Application channel (SVRCONN) for '$name'" "$MQ_APP_CHANNEL")"
            QMGR_NAMES+=("$name"); QMGR_PORTS+=("$port"); QMGR_CHANNELS+=("$chan")
        done
    fi
    # Mirror the first values as the "main QM" for dependent defaults (e.g. cert DN)
    MQ_QMGR_NAME="${QMGR_NAMES[0]}"
    MQ_LISTENER_PORT="${QMGR_PORTS[0]}"
    MQ_APP_CHANNEL="${QMGR_CHANNELS[0]}"

    echo
    MQ_APP_USER="$(ask 'Non-privileged application user (for all QMs)' "$MQ_APP_USER")"
    MQ_APP_GROUP="$(ask 'OS group for permissions (instead of per user)' "$MQ_APP_GROUP")"
    MQ_EXPLORER_CHANNEL="$(ask 'Dedicated channel ONLY for MQ Explorer/admin tools (separate from the app channel, for all QMs)' "$MQ_EXPLORER_CHANNEL")"
    MQ_APP_QUEUE="$(ask 'Sample application queue per QM (empty = none)' "$MQ_APP_QUEUE")"
    MQ_DLQ="$(ask 'Dead letter queue (name)' "$MQ_DLQ")"
    MQ_LOG_TYPE="$(ask 'Logging type (circular/linear)' "$MQ_LOG_TYPE")"
    MQ_LOG_PRIMARY="$(ask 'Primary log size in 4K blocks (default 4096)' "$MQ_LOG_PRIMARY")"
    if [[ "$MQ_LOG_TYPE" == "linear" ]]; then
        MQ_LOG_SECONDARY="$(ask 'Secondary log size in 4K blocks (default 1024)' "$MQ_LOG_SECONDARY")"
    fi

    echo
    narrate "==== Further common QM parameters ===="
    MQ_MAXMSGL="$(ask 'Max. message length in bytes (MAXMSGL)' "$MQ_MAXMSGL")"
    MQ_MAXCHL="$(ask 'Max. number of defined channels (MAXCHL)' "$MQ_MAXCHL")"
    MQ_MAXACTCHL="$(ask 'Max. number of concurrently active channels (MAXACTCHL)' "$MQ_MAXACTCHL")"
    MQ_DESCR="$(ask 'Description of the queue manager (DESCR, optional)' "$MQ_DESCR")"

    # ---- Security features / optional components / details / summary ----
    # Step chain with back navigation:
    #   WSTEP=1 Security features   (cancel -> cancel_to_menu(), straight back to the main menu)
    #   WSTEP=2 Optional components (cancel -> cancel_to_menu(), straight back to the main menu)
    #   WSTEP=3 TLS/web details + summary
    #           ("No" at the confirmation -> back to WSTEP=1 for adjustments)
    local WSTEP=1
    while true; do
        case "$WSTEP" in
            1)
                echo
                select_security_features
                WSTEP=2
                ;;
            2)
                echo
                select_optional_components
                WSTEP=3
                ;;
            3)
                if [[ "$SEC_TLS" == "yes" ]]; then
                    TLS_CIPHER="$(ask 'TLS CipherSpec' "$TLS_CIPHER")"
                    TLS_CERT_DN="$(ask 'Certificate DN' "CN=${MQ_QMGR_NAME},O=Example,C=DE")"
                fi

                # ---- MQ Web Console: ask for user/password ----
                if [[ "$INST_WEB" == "yes" ]]; then
                    echo
                    narrate "==== MQ Web Console (admin access) ===="
                    narrate "Note: this user exists only in the mqweb registry (no OS account needed)."
                    WEB_ADMIN_USER="$(ask 'Web admin user name' "$WEB_ADMIN_USER")"
                    WEB_ADMIN_PASS="$(ask_secret 'Web admin password' "$WEB_ADMIN_PASS")"
                    if [[ "$(ask_yes_no 'Create an additional read-only user (MQWebAdminRO)?' 'no')" == "yes" ]]; then
                        WEB_RO_USER="$(ask 'Read-only user name' "${WEB_RO_USER:-mqreader}")"
                        WEB_RO_PASS="$(ask_secret 'Read-only password' "$WEB_RO_PASS")"
                    fi
                    WEB_REMOTE="$(ask_yes_no 'Allow remote access to the console (all interfaces)?' "$WEB_REMOTE")"
                    WEB_HTTPS_PORT="$(ask 'HTTPS port of the console' "$WEB_HTTPS_PORT")"
                fi

                echo
                narrate "==== Summary ===="
                local summary_text
                summary_text="$( {
                    echo "Queue managers (${#QMGR_NAMES[@]}):"
                    local k
                    for k in "${!QMGR_NAMES[@]}"; do
                        printf "  - %-12s Port %-6s Channel %s\n" \
                            "${QMGR_NAMES[$k]}" "${QMGR_PORTS[$k]}" "${QMGR_CHANNELS[$k]}"
                    done
                    cat <<EOF

App user         : $MQ_APP_USER (group: $MQ_APP_GROUP)
App queue per QM : ${MQ_APP_QUEUE:-<none>}
Dead letter queue: $MQ_DLQ
Logging          : $MQ_LOG_TYPE (primary $MQ_LOG_PRIMARY, secondary $MQ_LOG_SECONDARY)
MAXMSGL / MAXCHL / MAXACTCHL : $MQ_MAXMSGL / $MQ_MAXCHL / $MQ_MAXACTCHL
Description      : ${MQ_DESCR:-<none>}
CONNAUTH         : $SEC_CONNAUTH
CHLAUTH          : $SEC_CHLAUTH
Block privileged : $SEC_BLOCK_PRIV
TLS              : $SEC_TLS
AMS              : $SEC_AMS
Web Console      : $INST_WEB$( [[ "$INST_WEB" == "yes" ]] && echo " (admin: $WEB_ADMIN_USER, port $WEB_HTTPS_PORT, remote: $WEB_REMOTE)" )
Autostart        : $ENABLE_AUTOSTART
Aliases          : $ENABLE_ALIASES
EOF
                } )"
                if [[ "$UI_MODE" == "tui" ]]; then
                    # In TUI mode write only to the logfile (not to the terminal),
                    # the actual display is done by ui_summary_box right afterwards.
                    echo "$summary_text" >> "$LOGFILE"
                    ui_summary_box "Summary" "$summary_text"
                else
                    echo "$summary_text" | tee -a "$LOGFILE"
                fi
                if [[ "$(ask_yes_no 'Continue with these settings?' 'yes')" == "yes" ]]; then
                    break   # done – gather_parameters completed successfully
                else
                    info "Back to the security/component settings ..."
                    WSTEP=1
                fi
                ;;
        esac
    done
    return 0
}
gather_parameters

#-------------------------------------------------------------------------------
# 7-10) Software installation (only in mode "install"; "addqm" uses the existing MQ environment)
#-------------------------------------------------------------------------------
# Note: prepare_media(), accept_license() and post_install_setup() are
# already defined further above (section 5b, before main_menu), so that they can also
# be reused by perform_upgrade()/perform_feature_install().
install_rpm_packages() {
    narrate "Installing RPM packages ..."
    # Order: runtime first. Server, GSKit (TLS), SDK, samples, JRE/Java.
    local pkgs=( MQSeriesRuntime MQSeriesServer MQSeriesGSKit MQSeriesSDK MQSeriesSamples MQSeriesMan )
    [[ "$SEC_TLS" == "yes" || "$SEC_AMS" == "yes" || "$INST_WEB" == "yes" ]] && pkgs+=( MQSeriesJRE MQSeriesJava )
    [[ "$SEC_AMS" == "yes" ]]  && pkgs+=( MQSeriesAMS )
    [[ "$INST_WEB" == "yes" ]] && pkgs+=( MQSeriesWeb )

    local files=()
    for p in "${pkgs[@]}"; do
        local f
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${p}-*.rpm" | head -n1 || true)"
        if [[ -n "$f" ]]; then files+=( "$f" ); else warn "Package not found (skipped): $p"; fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "No RPM packages found."

    # rpm -ivh installs in the given order with dependency checking.
    # --oldpackage/--replacepkgs only for a forced reinstallation over existing packages.
    local rpm_flags=(-ivh)
    [[ "$FORCE_REINSTALL" == "yes" ]] && rpm_flags=(-ivh --oldpackage --replacepkgs --replacefiles)
    run_with_progress "Installing ${#files[@]} RPM package(s) (may take 1-2 minutes) ..." \
        rpm "${rpm_flags[@]}" "${files[@]}" || die "RPM installation failed. Check logfile: $LOGFILE"
    info "RPM packages installed."
}

install_deb_packages() {
    narrate "Installing DEB packages ..."
    local pkgs=( ibmmq-runtime ibmmq-server ibmmq-gskit ibmmq-sdk ibmmq-samples ibmmq-man )
    [[ "$SEC_TLS" == "yes" || "$SEC_AMS" == "yes" || "$INST_WEB" == "yes" ]] && pkgs+=( ibmmq-jre ibmmq-java )
    [[ "$SEC_AMS" == "yes" ]]  && pkgs+=( ibmmq-ams )
    [[ "$INST_WEB" == "yes" ]] && pkgs+=( ibmmq-web )

    local files=()
    for p in "${pkgs[@]}"; do
        local f
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${p}_*.deb" | head -n1 || true)"
        if [[ -n "$f" ]]; then files+=( "$f" ); else warn "Package not found (skipped): $p"; fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "No DEB packages found."

    export DEBIAN_FRONTEND=noninteractive
    # apt resolves local inter-dependencies of the given .deb files.
    # --allow-downgrades/--allow-remove-essential only for a forced reinstallation.
    local apt_flags=(-y install)
    [[ "$FORCE_REINSTALL" == "yes" ]] && apt_flags=(-y --allow-downgrades install)
    run_with_progress "Installing ${#files[@]} DEB package(s) (may take 1-2 minutes) ..." \
        apt-get "${apt_flags[@]}" "${files[@]}" || die "DEB installation failed. Check logfile: $LOGFILE"
    info "DEB packages installed."
}

install_mq_software() {
    prepare_media
    accept_license

    local _existing_check
    _existing_check="$(check_existing_mq_packages)"
    info "Check for existing IBM MQ packages (package format: $PKG_FORMAT): result='$_existing_check'"
    if [[ "$_existing_check" == "yes" ]]; then
        local installed_ver media_ver
        installed_ver="$(get_installed_mq_version)"
        media_ver="$(get_media_mq_version)"
        info "Installed version: ${installed_ver:-unknown}  |  media version: ${media_ver:-unknown}"

        if [[ "$(would_be_real_downgrade "$installed_ver" "$media_ver")" == "yes" ]]; then
            warn "ATTENTION: The installed IBM MQ packages (version $installed_ver) are NEWER than this"
            warn "media (version $media_ver). IBM MQ does NOT support a downgrade to a lower"
            warn "version/release/modification level - the IBM package installation script itself"
            warn "refuses this (error 'Downgrading ... is not supported'), regardless of"
            warn "apt/rpm options such as --allow-downgrades. Forcing it is NOT possible."
            die "Aborted: a real downgrade ($installed_ver -> $media_ver) is not supported by IBM MQ. Options: (1) use installation media with version >= $installed_ver, or (2) completely remove the existing installation (e.g. 'apt purge ibmmq*' or 'rpm -e' of all MQSeries* packages, then check remnants in /var/mqm/qmgrs and /var/mqm/log) and install again afterwards."
        fi

        warn "IBM MQ packages are already installed on this host."
        warn "'New installation' is intended for a fresh host. If you continue anyway,"
        warn "apt/rpm may UPDATE/REINSTALL existing packages to the version of this media"
        warn "and in doing so completely REMOVE components not selected in this run (e.g. AMQP, AMS,"
        warn "client tools, File Transfer, MQTT/Telemetry, language packs)."
        warn "Recommended: main menu -> 'Upgrade' (updates in a controlled way, removes nothing) or"
        warn "use 'Install an add-on feature' or 'Add another queue manager'."
        local proceed="$FORCE_REINSTALL"
        if [[ -z "$proceed" ]]; then
            proceed="$(ask_yes_no 'Existing IBM MQ installation detected. Continue with the new installation anyway (may change/remove packages)?' 'no')"
        fi
        if [[ "$proceed" != "yes" ]]; then
            cancel_to_menu "Aborted: existing IBM MQ installation detected. Please choose 'Upgrade', 'Add another queue manager' or 'Install an add-on feature' in the main menu (or set MQ_MODE accordingly)."
        fi
        FORCE_REINSTALL="yes"
        warn "Continuing with forced reinstallation (--allow-downgrades / --oldpackage active) ..."
    fi

    ui_menu_intro "Installing IBM MQ packages ($PKG_FORMAT)"
    case "$PKG_FORMAT" in
        rpm) install_rpm_packages ;;
        deb) install_deb_packages ;;
    esac
    post_install_setup
    tune_os_for_mq
}

if [[ "$MODE" == "install" ]]; then
    install_mq_software
else
    info "Mode 'addqm': skipping package installation, using the existing installation under '$MQ_INSTALL_PATH'."
    source_mqenv
    info "IBM MQ version (existing installation):"
    dspmqver | tee -a "$LOGFILE"
    MQ_INSTALLED_VERSION="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
fi

#-------------------------------------------------------------------------------
# 11) User/group best practice
#-------------------------------------------------------------------------------
# Ensures that a single sysctl parameter has AT LEAST the
# IBM-recommended value - only raises it, NEVER lowers an already
# higher (better) value. Outputs the resulting (final) value.
sysctl_ensure_min() {
    local param="$1" min_val="$2"
    local current; current="$(sysctl -n "$param" 2>/dev/null)" || current=""
    if [[ "$current" =~ ^[0-9]+$ ]] && [[ "$current" -ge "$min_val" ]]; then
        narrate "  $param = $current (already >= IBM minimum $min_val, unchanged)"
        echo "$current"
    else
        narrate "  $param: '${current:-unknown}' -> $min_val (raised to IBM minimum)"
        echo "$min_val"
    fi
}

# Sets IBM-documented kernel parameters and ulimits for MQ (see IBM docs
# "Configuring the operating system on Linux"). All values are MINIMUM values -
# an already higher/better existing value is never lowered. Additionally
# LimitNOFILE/LimitNPROC are added to the QM systemd units, since PAM-
# based ulimits (limits.conf) do NOT apply to services started via systemd
# according to the IBM docs.
tune_os_for_mq() {
    local proceed="$OS_TUNE_MQ"
    if [[ -z "$proceed" ]]; then
        proceed="$(ask_yes_no 'Set IBM-recommended kernel/limit tuning values for MQ (only raise, never lower)?' 'yes')"
    fi
    if [[ "$proceed" != "yes" ]]; then
        info "OS tuning for MQ skipped (user choice)."
        return 0
    fi
    info "Checking/setting IBM-recommended kernel parameters for MQ ..."

    local shmmni shmall shmmax filemax pidmax threadsmax
    shmmni="$(sysctl_ensure_min kernel.shmmni 4096)"
    shmall="$(sysctl_ensure_min kernel.shmall 2097152)"
    shmmax="$(sysctl_ensure_min kernel.shmmax 268435456)"
    filemax="$(sysctl_ensure_min fs.file-max 524288)"
    # The IBM docs state 120000 (not 12000 - some copied templates are
    # missing a zero; 12000 would often be a degradation on modern systems)
    pidmax="$(sysctl_ensure_min kernel.pid_max 120000)"
    threadsmax="$(sysctl_ensure_min kernel.threads-max 48000)"

    # kernel.sem has 4 values (SEMMSL SEMMNS SEMOPM SEMMNI) - raise each one
    # individually only, IBM minimum: 500 256000 250 1024
    local sem_current sem_min=(500 256000 250 1024) sem_out=()
    sem_current="$(sysctl -n kernel.sem 2>/dev/null)" || sem_current="0 0 0 0"
    local -a sem_cur_a=(); read -r -a sem_cur_a <<< "$sem_current"
    local i
    for i in 0 1 2 3; do
        if [[ "${sem_cur_a[$i]:-0}" =~ ^[0-9]+$ ]] && [[ "${sem_cur_a[$i]:-0}" -ge "${sem_min[$i]}" ]]; then
            sem_out+=("${sem_cur_a[$i]}")
        else
            sem_out+=("${sem_min[$i]}")
        fi
    done
    local sem_final="${sem_out[*]}"
    if [[ "$sem_final" != "$sem_current" ]]; then
        narrate "  kernel.sem: '$sem_current' -> '$sem_final' (individual values raised to IBM minimum)"
    else
        narrate "  kernel.sem = '$sem_current' (already >= IBM minimum, unchanged)"
    fi

    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-ibmmq.conf <<EOF
# IBM MQ recommended kernel parameters (set automatically by install-ibmmq.sh)
# Only raised, never lowered below an already better value.
kernel.shmmni = $shmmni
kernel.shmall = $shmall
kernel.shmmax = $shmmax
kernel.sem = $sem_final
fs.file-max = $filemax
kernel.pid_max = $pidmax
kernel.threads-max = $threadsmax
EOF
    sysctl -p /etc/sysctl.d/99-ibmmq.conf >>"$LOGFILE" 2>&1 \
        || warn "sysctl -p reported problems (e.g. in containers with read-only /proc) - check the logfile."
    info "Kernel parameters set in /etc/sysctl.d/99-ibmmq.conf and applied."

    # ulimits for mqm/root - apply to normal logins/PAM sessions.
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-ibmmq.conf <<EOF
# IBM MQ recommended resource limits (set automatically by install-ibmmq.sh)
mqm             hard    nofile          $MQ_NOFILE_LIMIT
mqm             soft    nofile          $MQ_NOFILE_LIMIT
mqm             hard    nproc           $MQ_NPROC_LIMIT
mqm             soft    nproc           $MQ_NPROC_LIMIT
root            hard    nofile          $MQ_NOFILE_LIMIT
root            soft    nofile          $MQ_NOFILE_LIMIT
EOF
    info "Resource limits set in /etc/security/limits.d/99-ibmmq.conf (effective from the next login/session)."
    narrate "Note: PAM limits (limits.conf) do NOT apply to queue managers started via systemd -"
    narrate "for that this script sets LimitNOFILE/LimitNPROC directly in the QM systemd units (see setup_autostart)."
}

setup_users() {
    info "Checking users/groups ..."
    # 'mqm' is created by the packages. Check to be safe.
    getent group mqm >/dev/null || groupadd mqm
    id mqm >/dev/null 2>&1 || useradd -g mqm -d /var/mqm -s /usr/sbin/nologin mqm 2>/dev/null || true

    # Best practice: dedicated, NON-privileged application user
    # (not a member of 'mqm' -> treated by the OAM as a normal user)
    if ! id "$MQ_APP_USER" >/dev/null 2>&1; then
        useradd -M -s /usr/sbin/nologin "$MQ_APP_USER" 2>/dev/null \
            || useradd -M -s /bin/false "$MQ_APP_USER"
        info "Application user '$MQ_APP_USER' created (non-privileged)."
    else
        info "Application user '$MQ_APP_USER' already exists."
    fi
    if id -nG "$MQ_APP_USER" | grep -qw mqm; then
        warn "'$MQ_APP_USER' is a member of 'mqm' (= privileged). Best practice: NOT in 'mqm'."
    fi

    # Permission group: setmqaut is granted to this group instead of
    # individual users (IBM best practice) - new app users or MCAUSERs
    # of additional channels then only need to become members here,
    # instead of running setmqaut again each time.
    getent group "$MQ_APP_GROUP" >/dev/null || {
        groupadd "$MQ_APP_GROUP"
        info "Permission group '$MQ_APP_GROUP' created."
    }
    if ! id -nG "$MQ_APP_USER" | grep -qw "$MQ_APP_GROUP"; then
        usermod -aG "$MQ_APP_GROUP" "$MQ_APP_USER"
        info "'$MQ_APP_USER' added to group '$MQ_APP_GROUP'."
    fi
}
setup_users

#-------------------------------------------------------------------------------
# 12-15) Per queue manager: create, start, TLS, security MQSC, permissions
#         provision_qmgr <name> <port> <channel>
#-------------------------------------------------------------------------------
provision_qmgr() {
    local qm="$1" port="$2" chan="$3"
    info "================ Queue manager: $qm (port $port, channel $chan) ================"

    # --- 12) Create + start ---
    if su -s /bin/bash mqm -c "dspmq" 2>/dev/null | grep -qw "QMNAME($qm)"; then
        warn "Queue manager '$qm' already exists – skipping crtmqm."
    else
        local logopt="-lc"
        [[ "$MQ_LOG_TYPE" == "linear" ]] && logopt="-ll"
        su -s /bin/bash mqm -c "crtmqm $logopt -u '$MQ_DLQ' '$qm'" >>"$LOGFILE" 2>&1 \
            || die "crtmqm for '$qm' failed."
        info "Queue manager '$qm' created."

        # MAXCHL/MAXACTCHL are NOT valid ALTER QMGR parameters, but
        # are set in the qm.ini file (stanza "Channels:"). This must happen
        # BEFORE the first start so it takes effect immediately - for
        # an already running/existing QM a restart would be needed,
        # hence only here in the "freshly created" branch.
        if [[ -f "/var/mqm/qmgrs/${qm}/qm.ini" ]]; then
            info "Setting MAXCHL/MAXACTCHL for '$qm' in qm.ini (before the first start) ..."
            {
                echo ""
                echo "Channels:"
                echo "   MaxChannels=$MQ_MAXCHL"
                echo "   MaxActiveChannels=$MQ_MAXACTCHL"
            } >> "/var/mqm/qmgrs/${qm}/qm.ini"
            chown mqm:mqm "/var/mqm/qmgrs/${qm}/qm.ini" 2>/dev/null || true
        else
            warn "qm.ini for '$qm' not found - MAXCHL/MAXACTCHL could not be set."
        fi
    fi
    start_qmgr_robust "$qm"

    # --- 13) TLS (optional, own repository/certificate per QM) ---
    local tls_keyr="" tls_label=""
    if [[ "$SEC_TLS" == "yes" ]]; then
        local ssldir="/var/mqm/qmgrs/${qm}/ssl"
        local keydb="${ssldir}/key"
        tls_label="qm.${qm,,}"
        local dn_rest="${TLS_CERT_DN#*,}"          # everything after the first comma
        [[ "$dn_rest" == "$TLS_CERT_DN" ]] && dn_rest="O=Example,C=DE"
        local cert_dn="CN=${qm},${dn_rest}"
        local tlspw; tlspw="$(openssl rand -base64 18 2>/dev/null || echo "Chg-Me-$(date +%s)")"
        su -s /bin/bash mqm -c "mkdir -p '$ssldir'"
        su -s /bin/bash mqm -c \
          "runmqakm -keydb -create -db '${keydb}.kdb' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
          || die "runmqakm: key repository for '$qm' failed."
        su -s /bin/bash mqm -c \
          "runmqakm -cert -create -db '${keydb}.kdb' -stashed -label '$tls_label' \
             -dn '$cert_dn' -size 2048 -sig_alg SHA256WithRSA -expire 365" >>"$LOGFILE" 2>&1 \
          || die "runmqakm: certificate for '$qm' failed."
        tls_keyr="$keydb"
        info "TLS for '$qm': ${keydb}.kdb (label $tls_label)"
    fi

    # --- 14) Generate and apply the security MQSC ---
    local mqsc="${WORKDIR:-/tmp}/configure_${qm}.mqsc"
    # Escape single quotes in the DESCR text for MQSC ('->'')
    local descr_escaped="${MQ_DESCR//\'/\'\'}"
    {
        echo "* === Auto-generated for $qm: $(date) ==="
        echo "* Common QM parameters (MAXCHL/MAXACTCHL are set separately via qm.ini,"
        echo "* since they are NOT valid ALTER QMGR parameters)"
        echo "ALTER QMGR MAXMSGL($MQ_MAXMSGL) MAXHANDS(256) MAXUMSGS(10000) DEADQ('$MQ_DLQ')"
        if [[ -n "$MQ_DESCR" ]]; then
            echo "ALTER QMGR DESCR('$descr_escaped')"
        fi
        echo ""
        echo "DEFINE LISTENER('LISTENER.TCP') TRPTYPE(TCP) PORT($port) CONTROL(QMGR) REPLACE"
        echo "START LISTENER('LISTENER.TCP')"
        echo ""
        if [[ "$SEC_CONNAUTH" == "yes" ]]; then
            echo "DEFINE AUTHINFO('USE.PWD') AUTHTYPE(IDPWOS) +"
            echo "       CHCKLOCL(OPTIONAL) CHCKCLNT(REQUIRED) +"
            echo "       ADOPTCTX(YES) FAILDLAY(1) REPLACE"
            echo "ALTER QMGR CONNAUTH('USE.PWD')"
            echo "REFRESH SECURITY TYPE(CONNAUTH)"
        else
            echo "ALTER QMGR CONNAUTH(' ')"
            echo "REFRESH SECURITY TYPE(CONNAUTH)"
        fi
        echo ""
        if [[ "$SEC_CHLAUTH" == "yes" ]]; then
            echo "ALTER QMGR CHLAUTH(ENABLED)"
        else
            echo "ALTER QMGR CHLAUTH(DISABLED)"
            echo "* WARN: CHLAUTH disabled – not recommended!"
        fi
        echo ""
        if [[ "$SEC_BLOCK_PRIV" == "yes" ]]; then
            echo "SET CHLAUTH('*') TYPE(BLOCKUSER) USERLIST('nobody','*MQADMIN') +"
            echo "    DESCR('Block privileged users') ACTION(REPLACE)"
            echo "SET CHLAUTH(SYSTEM.DEF.SVRCONN)   TYPE(BLOCKUSER) USERLIST('*MQADMIN') ACTION(REPLACE)"
            echo "SET CHLAUTH(SYSTEM.ADMIN.SVRCONN) TYPE(BLOCKUSER) USERLIST('*MQADMIN') ACTION(REPLACE)"
            echo ""
        fi
        echo "* Dedicated application channel with a fixed, non-privileged MCAUSER"
        if [[ "$SEC_TLS" == "yes" ]]; then
            echo "DEFINE CHANNEL('$chan') CHLTYPE(SVRCONN) +"
            echo "       MCAUSER('$MQ_APP_USER') +"
            echo "       SSLCIPH('$TLS_CIPHER') SSLCAUTH(OPTIONAL) REPLACE"
        else
            echo "DEFINE CHANNEL('$chan') CHLTYPE(SVRCONN) MCAUSER('$MQ_APP_USER') REPLACE"
        fi
        echo ""
        if [[ "$SEC_CHLAUTH" == "yes" ]]; then
            echo "SET CHLAUTH('$chan') TYPE(ADDRESSMAP) ADDRESS('*') +"
            echo "    USERSRC(CHANNEL) CHCKCLNT(REQUIRED) +"
            echo "    DESCR('Application access') ACTION(REPLACE)"
            echo ""
        fi
        # Separate, dedicated channel ONLY for MQ Explorer/admin tools - deliberately
        # separated from the application channel, so that e.g. CHLAUTH rules or later
        # disabling/restricting can happen independently of the application
        # (IBM best practice: do not mix admin/tool access with application access).
        echo "* Dedicated channel ONLY for MQ Explorer/admin tools (separate from applications)"
        if [[ "$SEC_TLS" == "yes" ]]; then
            echo "DEFINE CHANNEL('$MQ_EXPLORER_CHANNEL') CHLTYPE(SVRCONN) +"
            echo "       MCAUSER('$MQ_APP_USER') +"
            echo "       SSLCIPH('$TLS_CIPHER') SSLCAUTH(OPTIONAL) REPLACE"
        else
            echo "DEFINE CHANNEL('$MQ_EXPLORER_CHANNEL') CHLTYPE(SVRCONN) MCAUSER('$MQ_APP_USER') REPLACE"
        fi
        echo ""
        if [[ "$SEC_CHLAUTH" == "yes" ]]; then
            echo "SET CHLAUTH('$MQ_EXPLORER_CHANNEL') TYPE(ADDRESSMAP) ADDRESS('*') +"
            echo "    USERSRC(CHANNEL) CHCKCLNT(REQUIRED) +"
            echo "    DESCR('MQ Explorer/admin tool access') ACTION(REPLACE)"
            echo ""
        fi
        if [[ "$SEC_TLS" == "yes" ]]; then
            echo "ALTER QMGR SSLKEYR('${tls_keyr}') CERTLABL('${tls_label}')"
            echo "REFRESH SECURITY TYPE(SSL)"
            echo ""
        fi
        if [[ -n "$MQ_APP_QUEUE" ]]; then
            echo "DEFINE QLOCAL('$MQ_APP_QUEUE') DEFPSIST(YES) REPLACE"
        fi
    } > "$mqsc"

    # Feed it via a pipe instead of file redirection: the file may be located in
    # a WORKDIR readable only by root (mktemp -d, mode 0700) - "cat"
    # runs as root and can read it, "su ... runmqsc" then simply receives the
    # content via standard input (no file open needed).
    cat "$mqsc" | su -s /bin/bash mqm -c "runmqsc '$qm'" >>"$LOGFILE" 2>&1 \
        || die "runmqsc for '$qm' failed. MQSC: $mqsc"
    cp "$mqsc" "/var/mqm/${qm}-configure.mqsc" 2>/dev/null || true
    info "Security MQSC applied for '$qm' (copy: /var/mqm/${qm}-configure.mqsc)."

    # --- 15) Minimal permissions (least privilege) - granted to the GROUP,
    #         not to the individual user (IBM best practice): further
    #         app users/MCAUSERs of additional channels then only need to
    #         become members of this group, instead of needing setmqaut again.
    su -s /bin/bash mqm -c \
      "setmqaut -m '$qm' -t qmgr -g '$MQ_APP_GROUP' +connect +inq" >>"$LOGFILE" 2>&1 \
      || warn "setmqaut (qmgr) for '$qm' failed."
    if [[ -n "$MQ_APP_QUEUE" ]]; then
        su -s /bin/bash mqm -c \
          "setmqaut -m '$qm' -n '$MQ_APP_QUEUE' -t queue -g '$MQ_APP_GROUP' +put +get +browse +inq" \
          >>"$LOGFILE" 2>&1 || warn "setmqaut (queue) for '$qm' failed."
    fi
    info "Permissions set for '$qm' (least privilege, group: $MQ_APP_GROUP)."
}

# Provision all queue managers one after another
ui_menu_intro "Setting up ${#QMGR_NAMES[@]} queue manager(s)"
for _i in "${!QMGR_NAMES[@]}"; do
    provision_qmgr "${QMGR_NAMES[$_i]}" "${QMGR_PORTS[$_i]}" "${QMGR_CHANNELS[$_i]}"
done

#-------------------------------------------------------------------------------
# 14b) Convenience aliases (tail-/mqsc-/status-/... per QM)
#-------------------------------------------------------------------------------
# Aliases instead of symlinks: they wrap the complete command (incl. running as
# the 'mqm' user for runmqsc/dspmq/strmqm/endmqm) and thereby actually save
# typing - a plain path symlink does not. Regenerated completely on EVERY run
# from ALL queue managers currently known on the host
# (not only the ones created in this run), so that a later
# "Add another QM" does not lose aliases for already existing
# QMs. Placed system-wide in /etc/profile.d/ (NOT in the
# .profile of the 'mqm' user - as a service account it typically has
# 'nologin' as its shell, so a login as 'mqm' never happens and
# a .profile there would never be loaded; the actual users are the
# admins logging in via SSH/sudo).
setup_aliases() {
    [[ "$ENABLE_ALIASES" == "yes" ]] || return 0
    local all_qms; all_qms="$(get_all_qm_names)"
    [[ -n "$all_qms" ]] || return 0

    local afile="/etc/profile.d/mqm-aliases.sh"
    {
        echo "# IBM MQ troubleshooting/admin aliases (generated automatically by install-ibmmq.sh)"
        echo "# Regenerated on every run - manual changes will be lost."
        echo "# Overview: tail-/mqsc-/status-/start-/stop-/chstatus-/qdepth-/xmitq-<qm>  plus global: mqver, qmlist"
        local qm aname
        while IFS= read -r qm; do
            [[ -n "$qm" ]] || continue
            # Alias name: lowercase, everything except a-z0-9 becomes '_'
            # (QM names may contain '.'/'-', which do not work in alias names)
            aname="$(printf '%s' "${qm,,}" | tr -c 'a-z0-9' '_')"
            # Follow the current error log (follows the rotation, see -F instead of -f)
            echo "alias tail-${aname}='tail -F /var/mqm/qmgrs/${qm}/errors/AMQERR01.LOG'"
            # Interactive MQSC session for this QM
            echo "alias mqsc-${aname}='su -s /bin/bash mqm -c \"runmqsc ${qm}\"'"
            # Short status of this one QM
            echo "alias status-${aname}='su -s /bin/bash mqm -c \"dspmq -m ${qm} -o status\"'"
            # Start/stop (controlled, waits for a clean shutdown)
            echo "alias start-${aname}='su -s /bin/bash mqm -c \"strmqm ${qm}\"'"
            echo "alias stop-${aname}='su -s /bin/bash mqm -c \"endmqm -w ${qm}\"'"
            # Channel status - most common diagnosis for connection problems
            echo "alias chstatus-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY CHSTATUS(*) ALL\\\" | runmqsc ${qm}\"'"
            # Queue depths (with MAXDEPTH as reference, not just a bare number) -
            # most common diagnosis for message backlogs
            echo "alias qdepth-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY QUEUE(*) CURDEPTH MAXDEPTH TYPE(QLOCAL)\\\" | runmqsc ${qm}\"'"
            # Transmission queue depths: own, focused view on channels to
            # other queue managers (cluster/point-to-point/MQTT transmission queue) -
            # a growing XMITQ usually indicates a stopped/hanging
            # sender channel, and is otherwise easily missed in the normal queue list
            echo "alias xmitq-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY QUEUE(*) WHERE(USAGE EQ XMITQ) CURDEPTH MAXDEPTH\\\" | runmqsc ${qm}\"'"
        done <<< "$all_qms"
        # Global (not QM-specific) short commands
        echo "alias mqver='dspmqver'"
        echo "alias qmlist='su -s /bin/bash mqm -c \"dspmq -o status -o installation\"'"
    } > "$afile" 2>>"$LOGFILE" || { warn "Could not write '$afile' - aliases skipped."; return 0; }
    chmod 644 "$afile" 2>/dev/null || true
    narrate "Aliases per QM (tail-/mqsc-/status-/start-/stop-/chstatus-/qdepth-/xmitq-<qm>) plus global (mqver, qmlist)"
    narrate "created in: $afile (effective after a new login)"
}
setup_aliases

#-------------------------------------------------------------------------------
# 15b) Set up the MQ Web Console (mqweb) – users/passwords/roles
#-------------------------------------------------------------------------------
configure_web_console() {
    [[ "$INST_WEB" == "yes" ]] || return 0
    info "Configuring the MQ Web Console (mqweb) ..."

    # Determine the installation name (default: Installation1)
    local instname webdir
    instname="$("$MQ_INSTALL_PATH/bin/dspmqinst" 2>/dev/null | awk -F': *' '/InstName/{print $2; exit}')" || true
    instname="${instname:-Installation1}"

    # Find or create the mqweb server directory
    webdir="$(find /var/mqm/web/installations -maxdepth 3 -type d -name mqweb 2>/dev/null | head -n1)"
    if [[ -z "$webdir" ]]; then
        webdir="/var/mqm/web/installations/${instname}/servers/mqweb"
        mkdir -p "$webdir"
    fi
    info "mqweb configuration directory: $webdir"

    # Encode passwords with securityUtility (hash preferred, otherwise xor)
    local secutil="$MQ_INSTALL_PATH/web/bin/securityUtility"
    encode_pw() {
        local plain="$1" enc=""
        if [[ -x "$secutil" ]]; then
            enc="$("$secutil" encode --encoding=hash "$plain" 2>/dev/null | grep -E '^\{' | tail -n1)"
            [[ -z "$enc" ]] && enc="$("$secutil" encode "$plain" 2>/dev/null | grep -E '^\{' | tail -n1)"
        fi
        if [[ -n "$enc" ]]; then echo "$enc"; else
            warn "securityUtility not available – the password is stored in plain text!"
            echo "$plain"
        fi
    }

    local admin_pw_enc ro_user_xml="" ro_role_console="" ro_role_rest=""
    admin_pw_enc="$(encode_pw "$WEB_ADMIN_PASS")"

    if [[ -n "$WEB_RO_USER" ]]; then
        local ro_pw_enc; ro_pw_enc="$(encode_pw "$WEB_RO_PASS")"
        ro_user_xml="        <user name=\"$WEB_RO_USER\" password=\"$ro_pw_enc\"/>"
        ro_role_console="            <security-role name=\"MQWebAdminRO\"><user name=\"$WEB_RO_USER\" realm=\"defaultRealm\"/></security-role>"
        ro_role_rest="$ro_role_console"
    fi

    # Back up the existing configuration
    [[ -f "$webdir/mqwebuser.xml" ]] && cp -a "$webdir/mqwebuser.xml" "$webdir/mqwebuser.xml.bak-$(date +%s)"

    # Generate a new mqwebuser.xml (basic registry + role mapping)
    cat > "$webdir/mqwebuser.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<server>
    <featureManager>
        <feature>appSecurity-2.0</feature>
        <feature>basicAuthenticationMQ-1.0</feature>
    </featureManager>

    <!-- Basic registry: users exist only here (no OS account needed).
         Passwords are encoded with securityUtility. -->
    <basicRegistry id="basic" realm="defaultRealm">
        <user name="$WEB_ADMIN_USER" password="$admin_pw_enc"/>
$ro_user_xml
        <group name="MQWebAdminGroup" realm="defaultRealm">
            <member name="$WEB_ADMIN_USER"/>
        </group>
    </basicRegistry>

    <!-- Roles for the IBM MQ Console -->
    <enterpriseApplication id="com.ibm.mq.console">
        <application-bnd>
            <security-role name="MQWebAdmin">
                <group name="MQWebAdminGroup" realm="defaultRealm"/>
            </security-role>
$ro_role_console
        </application-bnd>
    </enterpriseApplication>

    <!-- Roles for the administrative REST API -->
    <enterpriseApplication id="com.ibm.mq.rest">
        <application-bnd>
            <security-role name="MQWebAdmin">
                <group name="MQWebAdminGroup" realm="defaultRealm"/>
            </security-role>
$ro_role_rest
        </application-bnd>
    </enterpriseApplication>
</server>
EOF
    chmod 600 "$webdir/mqwebuser.xml"
    chown root:root "$webdir/mqwebuser.xml" 2>/dev/null || true
    info "mqwebuser.xml written (permissions 600, backup if one existed)."

    # Configure host/port
    if [[ "$WEB_REMOTE" == "yes" ]]; then
        "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpHost -v "*" >>"$LOGFILE" 2>&1 \
            || warn "setmqweb httpHost failed."
        warn "Remote access enabled (all interfaces) – make sure to restrict it via firewall!"
    else
        "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpHost -v "localhost" >>"$LOGFILE" 2>&1 || true
    fi
    "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpsPort -v "$WEB_HTTPS_PORT" >>"$LOGFILE" 2>&1 \
        || warn "setmqweb httpsPort failed."

    # Start the mqweb server
    info "Starting the mqweb server (may take a few seconds) ..."
    "$MQ_INSTALL_PATH/bin/strmqweb" >>"$LOGFILE" 2>&1 \
        || warn "strmqweb reported an error (is the server possibly already running?)."

    # Firewall for the HTTPS port (only with remote access)
    if [[ "$WEB_REMOTE" == "yes" ]]; then
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="${WEB_HTTPS_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            info "firewalld: port $WEB_HTTPS_PORT/tcp opened."
        elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
            ufw allow "${WEB_HTTPS_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            info "ufw: port $WEB_HTTPS_PORT/tcp opened."
        fi
    fi

    # Determine the console URL
    WEB_URL="$("$MQ_INSTALL_PATH/bin/dspmqweb" 2>/dev/null | grep -oE 'https://[^ ]*console/' | head -n1)" || true
    [[ -z "$WEB_URL" ]] && WEB_URL="https://<host>:${WEB_HTTPS_PORT}/ibmmq/console/"
    narrate "MQ Web Console: $WEB_URL"
}
configure_web_console

#-------------------------------------------------------------------------------
# 16) Firewall note / opening
#-------------------------------------------------------------------------------
configure_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if [[ "$(ask_yes_no "Open port $MQ_LISTENER_PORT/tcp in firewalld?" 'yes')" == "yes" ]]; then
            firewall-cmd --permanent --add-port="${MQ_LISTENER_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            info "firewalld: port $MQ_LISTENER_PORT/tcp opened."
        fi
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
        if [[ "$(ask_yes_no "Open port $MQ_LISTENER_PORT/tcp in ufw?" 'yes')" == "yes" ]]; then
            ufw allow "${MQ_LISTENER_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            info "ufw: port $MQ_LISTENER_PORT/tcp opened."
        fi
    else
        warn "No active firewalld/ufw detected – open port $MQ_LISTENER_PORT/tcp manually if needed."
    fi
}
configure_firewall

#-------------------------------------------------------------------------------
# 17) systemd autostart (optional, IBM-recommended approach)
#-------------------------------------------------------------------------------
setup_autostart() {
    [[ "$ENABLE_AUTOSTART" == "yes" ]] || return 0
    command -v systemctl >/dev/null 2>&1 || { warn "systemd not available – autostart skipped."; return 0; }

    local qm unit
    for qm in "${QMGR_NAMES[@]}"; do
        info "Setting up the systemd service for QM '$qm' ..."
        unit="/etc/systemd/system/ibmmq-${qm}.service"
        cat > "$unit" <<EOF
[Unit]
Description=IBM MQ Queue Manager $qm
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=mqm
Group=mqm
# According to the IBM docs, PAM limits (limits.conf) do NOT apply to queue managers
# started via systemd - so set them explicitly here.
LimitNOFILE=$MQ_NOFILE_LIMIT
LimitNPROC=$MQ_NPROC_LIMIT
ExecStart=$MQ_INSTALL_PATH/bin/strmqm $qm
ExecStop=$MQ_INSTALL_PATH/bin/endmqm -w $qm
TimeoutStartSec=180
TimeoutStopSec=120
Restart=no

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "ibmmq-${qm}.service" >>"$LOGFILE" 2>&1 || \
            warn "Enabling ibmmq-${qm}.service failed."
        info "Autostart enabled: ibmmq-${qm}.service"
    done

    # mqweb server autostart (runs independently of the queue manager)
    if [[ "$INST_WEB" == "yes" ]]; then
        info "Setting up the systemd service for mqweb ..."
        local wunit="/etc/systemd/system/ibmmq-web.service"
        cat > "$wunit" <<EOF
[Unit]
Description=IBM MQ Web Console (mqweb)
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
User=mqm
Group=mqm
LimitNOFILE=$MQ_NOFILE_LIMIT
LimitNPROC=$MQ_NPROC_LIMIT
ExecStart=$MQ_INSTALL_PATH/bin/strmqweb
ExecStop=$MQ_INSTALL_PATH/bin/endmqweb
TimeoutStartSec=180
TimeoutStopSec=120
Restart=no

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ibmmq-web.service >>"$LOGFILE" 2>&1 || \
            warn "Enabling ibmmq-web.service failed."
        info "Autostart enabled: ibmmq-web.service"
    fi
}
setup_autostart

#-------------------------------------------------------------------------------
# 18) Verification
#-------------------------------------------------------------------------------
verify() {
    info "==== Verification ===="
    local qm
    for qm in "${QMGR_NAMES[@]}"; do
        su -s /bin/bash mqm -c "dspmq -m '$qm'" | tee -a "$LOGFILE" || true
        su -s /bin/bash mqm -c "echo 'DISPLAY LSSTATUS(*) STATUS' | runmqsc '$qm'" \
            2>/dev/null | grep -i status | tee -a "$LOGFILE" || true
    done
}
verify

#-------------------------------------------------------------------------------
# 19) Completion / notes incl. MQ Explorer connection parameters
#-------------------------------------------------------------------------------

# Determine host/IP for the connection
HOST_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo '<host>')"
HOST_IPS="$(hostname -I 2>/dev/null | tr -s ' ' | sed 's/ *$//')"
[[ -z "$HOST_IPS" ]] && HOST_IPS="<ip-address>"

cat <<EOF | tee -a "$LOGFILE"

================================================================================
 IBM MQ installation completed.
================================================================================
 Installed MQ version    : ${MQ_INSTALLED_VERSION:-unknown}
 Created queue managers  : ${#QMGR_NAMES[@]}
 App user                : $MQ_APP_USER   (non-privileged, MCAUSER of the channels)
 Permission group        : $MQ_APP_GROUP  (setmqaut rights are granted to this group)
 Host (FQDN)             : $HOST_FQDN
 Host (IP addresses)     : $HOST_IPS
 Logfile                 : $LOGFILE

 MANDATORY NEXT STEP:
   Set the password for the app user (CONNAUTH checks OS user/password):
       sudo passwd $MQ_APP_USER
EOF

# ---- MQ Explorer connection parameters per queue manager ----

# Persistent file for later reference (not only terminal/logfile)
EXPLORER_FILE="/var/mqm/mq-explorer-connections.txt"
if [[ -f "$EXPLORER_FILE" ]]; then
    # File already exists (e.g. from an earlier installation) - append
    # instead of overwriting, so that on a later "Add another QM" the
    # connection data of earlier queue managers is preserved.
    {
        echo ""
        echo "################################################################################"
        echo "# Updated: $(date '+%F %T')  (new run - previous entries are preserved)"
        echo "################################################################################"
    } >> "$EXPLORER_FILE" 2>/dev/null || EXPLORER_FILE="$LOGFILE"
else
    : > "$EXPLORER_FILE" 2>/dev/null || EXPLORER_FILE="$LOGFILE"  # fallback if not writable
fi

cat <<EOF | tee -a "$LOGFILE" "$EXPLORER_FILE"

================================================================================
 MQ EXPLORER – CONNECTION PARAMETERS
 (right-click on "Queue Managers" -> "Add Remote Queue Manager...")
 Queue managers configured in this run: ${#QMGR_NAMES[@]}
================================================================================
EOF
for _i in "${!QMGR_NAMES[@]}"; do
    _qm="${QMGR_NAMES[$_i]}"
    _port="${QMGR_PORTS[$_i]}"
    _chan="${QMGR_CHANNELS[$_i]}"
    {
        echo ""
        echo " Queue manager #$(( _i + 1 )): $_qm"
        echo " ---------------------------------------------------------------"
        echo "   Queue manager name .......... : $_qm"
        echo "   Host name or IP address ..... : $HOST_FQDN   (or: $HOST_IPS)"
        echo "   Port number ................. : $_port"
        echo ""
        echo "   >>> Connection via MQ EXPLORER / admin tools <<<"
        echo "   Server-connection channel ... : $MQ_EXPLORER_CHANNEL"
        if [[ "$SEC_CONNAUTH" == "yes" ]]; then
            echo "     User ID .................... : $MQ_APP_USER  (+ its OS password)"
        fi
        echo ""
        echo "   Connection for APPLICATIONS:"
        echo "   Server-connection channel ... : $_chan"
        if [[ "$SEC_CONNAUTH" == "yes" ]]; then
            echo "   [x] Enable user identification"
            echo "       User ID ................. : $MQ_APP_USER"
            echo "       Password ................ : <OS password of $MQ_APP_USER>"
        else
            echo "   [ ] User identification ..... : (CONNAUTH disabled)"
        fi
        if [[ "$SEC_TLS" == "yes" ]]; then
            echo "   [x] Enable SSL/TLS (applies to both channels above)"
            echo "       CipherSpec .............. : $TLS_CIPHER"
            echo "       QMGR certificate label .. : qm.${_qm,,}"
            echo "       Note: export the QM certificate from"
            echo "                /var/mqm/qmgrs/${_qm}/ssl/key.kdb"
            echo "                and import it into the client trust store."
        fi
    } | tee -a "$LOGFILE" "$EXPLORER_FILE"
done

# ---- Compact table overview (quick copy & paste) ----
{
    echo ""
    echo " Quick overview:"
    printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" "QUEUE MANAGER" "HOST" "PORT" "CHANNEL (APP)" "CHANNEL (EXPLORER)" "TLS"
    printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" "---------------" "-------------------------" "------" "-----------------" "-----------------" "----------"
    for _i in "${!QMGR_NAMES[@]}"; do
        printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" \
            "${QMGR_NAMES[$_i]}" "$HOST_FQDN" "${QMGR_PORTS[$_i]}" "${QMGR_CHANNELS[$_i]}" "$MQ_EXPLORER_CHANNEL" \
            "$( [[ "$SEC_TLS" == "yes" ]] && echo "yes" || echo "no" )"
    done
} | tee -a "$LOGFILE" "$EXPLORER_FILE"

# ---- All queue managers on this host (incl. ones already present from earlier runs) ----
if id mqm >/dev/null 2>&1; then
    _all_qm_raw="$(su -s /bin/bash mqm -c "dspmq -o status" 2>/dev/null || true)"
    if [[ -n "$_all_qm_raw" ]]; then
        {
            echo ""
            echo "================================================================================"
            echo " ALL QUEUE MANAGERS ON THIS HOST"
            echo "================================================================================"
            while IFS= read -r _line; do
                [[ -z "$_line" ]] && continue
                _name="$(echo "$_line" | sed -n "s/.*QMNAME(\([^)]*\)).*/\1/p")"
                _known="no"
                for _known_qm in "${QMGR_NAMES[@]}"; do
                    [[ "$_known_qm" == "$_name" ]] && _known="yes"
                done
                if [[ "$_known" == "yes" ]]; then
                    echo "   $_line   <- configured in this run, see details above"
                else
                    echo "   $_line   <- already present, check port/channel with 'runmqsc $_name' if needed"
                fi
            done <<< "$_all_qm_raw"
        } | tee -a "$LOGFILE" "$EXPLORER_FILE"
    fi
fi

info "MQ Explorer connection details saved to: $EXPLORER_FILE"

cat <<EOF | tee -a "$LOGFILE"

 Notes on the MQ Explorer connection:
   - MQ Explorer runs as a separate client; for a remote connection the
     respective listener port must be reachable through the firewall.
   - Since privileged admins are blocked on channels ($SEC_BLOCK_PRIV),
     connect with the non-privileged app user (see above).
   - Local access (on this host, as mqm) is also possible directly:
       sudo su - mqm -s /bin/bash -c "dspmq"
   - Complete connection details are always available in: $EXPLORER_FILE
EOF

if [[ "$SEC_TLS" == "yes" ]]; then
cat <<EOF | tee -a "$LOGFILE"

 TLS NOTE:
   A self-signed certificate was created per QM (for tests only).
   For production replace it with a CA-signed certificate and distribute it to the
   clients. On the client side set CipherSpec '$TLS_CIPHER'.
EOF
fi

if [[ "$INST_WEB" == "yes" ]]; then
cat <<EOF | tee -a "$LOGFILE"

 WEB CONSOLE (manages all queue managers on this host):
     URL            : ${WEB_URL:-https://<host>:${WEB_HTTPS_PORT}/ibmmq/console/}
     Admin user     : $WEB_ADMIN_USER  (role MQWebAdmin)$( [[ -n "$WEB_RO_USER" ]] && echo "
     Read-only user : $WEB_RO_USER  (role MQWebAdminRO)" )
     Remote access  : $WEB_REMOTE   (HTTPS port $WEB_HTTPS_PORT)
     Control        : strmqweb / endmqweb / dspmqweb  (service: ibmmq-web.service)
     Note: self-signed certificate -> a browser warning on the first visit
           is normal. Web users exist only in the mqweb registry.
EOF
fi

if [[ "$ENABLE_ALIASES" == "yes" ]]; then
    _qm_suffixes=""
    for _qm in "${QMGR_NAMES[@]}"; do
        _aname="$(printf '%s' "${_qm,,}" | tr -c 'a-z0-9' '_')"
        _qm_suffixes+="${_qm_suffixes:+, }${_aname}"
    done
cat <<EOF | tee -a "$LOGFILE"

 CONVENIENCE ALIASES (system-wide, effective after a new login):
     Per QM: tail-<qm> / mqsc-<qm> / status-<qm> / start-<qm> / stop-<qm> / chstatus-<qm> / qdepth-<qm> / xmitq-<qm>
     Available QM suffixes: $_qm_suffixes
     Global: mqver, qmlist
     Example: tail-${QMGR_NAMES[0],,} (follows the current error log, also across rotation)
     Full overview: main menu -> 'Show alias overview'
EOF
fi

cat <<EOF | tee -a "$LOGFILE"

 Best practices this script has already applied:
   - Dedicated, non-privileged app user (not a member of 'mqm')
   - CONNAUTH (CHCKCLNT REQUIRED) + CHLAUTH active (per QM)
   - Privileged admins blocked on channels
   - Own SVRCONN channel with a fixed MCAUSER instead of SYSTEM.DEF.SVRCONN
   - Minimal permissions via setmqaut (least privilege)$( [[ "$INST_WEB" == "yes" ]] && echo "
   - Web Console: basic registry, encoded passwords, role separation" )
================================================================================
EOF

if [[ "$UI_MODE" == "tui" ]]; then
    read -r _rows _cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Installation completed" \
        --msgbox "IBM MQ installation completed.\n\n${#QMGR_NAMES[@]} queue manager(s) configured in this run.\n\nMQ Explorer connection parameters are in:\n$EXPLORER_FILE\n\nFull logfile:\n$LOGFILE\n\nImportant: still set the password for '$MQ_APP_USER' (sudo passwd $MQ_APP_USER)." \
        "$_rows" "$_cols" 3>&1 1>&2 2>&3 || true
fi

info "Done."
exit 0
}

#-------------------------------------------------------------------------------
# 6) Outer loop: runs run_main_flow() in a subshell. A
#    user abort (cancel_to_menu(), reserved exit code 99) makes
#    the subshell end with exactly this code - regardless of how deeply
#    nested (ask()/ask_yes_no()/ask_secret(), any perform_*
#    function) the abort was triggered. The loop detects this and
#    simply shows main_menu again, instead of ending the script. Any
#    other exit code (0 = completed successfully, 1 = real error via
#    die()) ends the script as usual.
#-------------------------------------------------------------------------------
while true; do
    _flow_rc=0
    ( run_main_flow ) || _flow_rc=$?
    if [[ $_flow_rc -eq 99 ]]; then
        continue
    fi
    exit $_flow_rc
done
