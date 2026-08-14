#!/usr/bin/env bash
#===============================================================================
# install-ibmmq-9.4.sh
#
# IBM MQ 9.4.x / 10.0.x (LTS) – Installations- und Hardening-Script
# (Dateiname historisch gewachsen; das Script installiert unveraendert
#  sowohl IBM MQ 9.4.x als auch IBM MQ 10.0.x – siehe naechster Absatz.)
#
# Kompatibel mit IBM MQ 9.4.x (Continuous Delivery) und IBM MQ 10.0.x
# (Long Term Support, GA seit Juni 2026). Paketformate, mqlicense.sh,
# crtmqm/runmqsc-Syntax und die RPM/DEB-Namenskonvention (MQSeriesXYZ /
# ibmmq-xyz) sind zwischen diesen Versionen unveraendert, daher installiert
# dieses eine Script beide Codelevel unveraendert und automatisch – welche
# Version installiert wird, entscheidet einzig das mitgegebene --media.
#
# Unterstützte Plattformen:
#   - Red Hat Enterprise Linux 8/9/10 (und kompatible: Rocky, Alma)  -> RPM
#     (RHEL 8: nur mit IBM MQ 9.4.x; RHEL 9/10: mit IBM MQ 9.4.x und 10.0.x)
#     (RDQM/Multi-Instance mit HA-Kernel-Modul: nur RHEL x86-64)
#   - SUSE Linux Enterprise Server 15                              -> RPM
#   - Ubuntu 20.04/22.04/24.04 (x86-64)                            -> DEB
#   - Raspberry Pi 4/5 mit 64-Bit OS (Raspberry Pi OS / Ubuntu)   -> DEB (ARM64)
#   - Raspberry Pi mit 32-Bit OS                                  -> DEB (ARM32, "as-is")
#
# Hinweis TLS: Ab IBM MQ 9.2.0 ist TLS 1.3 fuer neu angelegte Queue Manager
# bereits Standard (qm.ini AllowTLSV13). Der Default-CipherSpec dieses
# Scripts (ANY_TLS12_OR_HIGHER) bleibt fuer 9.4.x und 10.0.x gueltig; pruefe
# bei Bedarf 'runmqakm -cipher -list' auf zusaetzliche, neuere CipherSpecs
# der jeweils installierten GSKit-Version.
#
# Funktionen:
#   - Plattform- und Architektur-Erkennung
#   - Interaktive Abfrage der MQ-Parameter (QM-Name, Port, Pakete ...)
#   - Abfrage und Aktivierung der Standard-Security-Features
#   - Anwendung der IBM Best Practices (CONNAUTH, CHLAUTH, dedizierter
#     App-User, minimale Berechtigungen, optional TLS)
#
# WICHTIG: Die MQ-Installationsmedien (tar.gz aus Passport Advantage oder
#          die Developer Edition) muessen lokal vorliegen. Dieses Script
#          laedt die Medien NICHT herunter (Lizenz-/Entitlement-Gruende).
#
# Aufruf:
#   sudo ./install-ibmmq-9.4.sh --media /pfad/zu/MQServer-10.0.0.x-Linux.tar.gz   (oder 9.4.0.x)
#   sudo ./install-ibmmq-9.4.sh --media /pfad/zu/entpacktem/MQServer-Verzeichnis
#   sudo ./install-ibmmq-9.4.sh --media <pfad> --non-interactive   (nutzt Defaults/ENV)
#
# Lizenz dieses Scripts: frei nutz- und anpassbar. Ohne Gewaehr.
#===============================================================================

set -Eeuo pipefail

#-------------------------------------------------------------------------------
# 0) Globale Defaults  (per ENV oder --non-interactive ueberschreibbar)
#-------------------------------------------------------------------------------
MQ_QMGR_NAME="${MQ_QMGR_NAME:-QM1}"          # Name des (ersten) Queue Managers
MQ_LISTENER_PORT="${MQ_LISTENER_PORT:-1414}" # TCP-Listener-Port des (ersten) QM
MQ_DLQ="${MQ_DLQ:-SYSTEM.DEAD.LETTER.QUEUE}" # Dead Letter Queue
MQ_APP_CHANNEL="${MQ_APP_CHANNEL:-APP.SVRCONN}" # Dedizierter App-Kanal (Default je QM)
MQ_EXPLORER_CHANNEL="${MQ_EXPLORER_CHANNEL:-EXPLORER.SVRCONN}" # Dedizierter Kanal NUR fuer MQ Explorer/Admin-Tools
MQ_APP_USER="${MQ_APP_USER:-mqapp}"          # Nicht-privilegierter App-User (gemeinsam)
MQ_APP_GROUP="${MQ_APP_GROUP:-mqappusers}"   # OS-Gruppe, auf die Berechtigungen vergeben werden
                                              # (statt einzeln je Benutzer - IBM Best Practice:
                                              # neue App-User/Kanaele einfach in diese Gruppe
                                              # aufnehmen, statt erneut setmqaut auszufuehren)
MQ_APP_QUEUE="${MQ_APP_QUEUE:-APP.QUEUE.1}"  # Beispiel-Anwendungsqueue (je QM)
MQ_INSTALL_PATH="${MQ_INSTALL_PATH:-/opt/mqm}"

# OS-Tuning fuer IBM MQ (Kernel-Parameter, ulimits) - IBM-dokumentierte
# MINDESTWERTE (siehe "Configuring the operating system on Linux" in der
# IBM-MQ-Doku); werden nur angehoben, nie abgesenkt. leer = interaktiv fragen.
OS_TUNE_MQ="${OS_TUNE_MQ:-}"
MQ_NOFILE_LIMIT="${MQ_NOFILE_LIMIT:-10240}"
MQ_NPROC_LIMIT="${MQ_NPROC_LIMIT:-4096}"

# Logging-Optionen (je QM)
MQ_LOG_TYPE="${MQ_LOG_TYPE:-circular}"       # circular | linear
MQ_LOG_PRIMARY="${MQ_LOG_PRIMARY:-4096}"     # Primaer-Log-Groesse in 4K-Bloecken (1st log)
MQ_LOG_SECONDARY="${MQ_LOG_SECONDARY:-1024}" # Sekundaer-Log-Groesse in 4K-Bloecken (2nd log, nur linear)

# Weitere gaengige Queue-Manager-Parameter (gemeinsam fuer alle QMs)
MQ_MAXMSGL="${MQ_MAXMSGL:-4194304}"          # Max. Nachrichtenlaenge in Byte (MAXMSGL), Default 4 MB
MQ_MAXCHL="${MQ_MAXCHL:-100}"                # Max. Anzahl definierter Kanaele (MAXCHL)
MQ_MAXACTCHL="${MQ_MAXACTCHL:-256}"          # Max. Anzahl gleichzeitig aktiver Kanaele (MAXACTCHL)
MQ_DESCR="${MQ_DESCR:-}"                     # Freitext-Beschreibung des QM (DESCR), optional

# Mehrere Queue Manager (1..x):
#   MQ_QMGRS="NAME[:PORT[:CHANNEL]]"
#   - Ports koennen als Bereich PORT_START-PORT_END angegeben werden
#   - Channel ist weiterhin optional und defaults zu MQ_APP_CHANNEL
#
#   z. B. MQ_QMGRS="QM1:1414,QM2:1415-1420:APP.SVRCONN,QM3:1421-1425"
#   -> QM1 Port 1414, QM2 Ports 1415-1420, QM3 Ports 1421-1425
#
# Wird MQ_QMGRS gesetzt, hat es Vorrang vor MQ_QMGR_NAME/PORT/CHANNEL.
MQ_QMGRS="${MQ_QMGRS:-}"
declare -a QMGR_NAMES=() QMGR_PORTS=() QMGR_CHANNELS=()

# Security-Schalter (yes/no)
SEC_CONNAUTH="${SEC_CONNAUTH:-yes}"          # Connection Authentication (User/PW)
SEC_CHLAUTH="${SEC_CHLAUTH:-yes}"            # Channel Authentication Records
SEC_BLOCK_PRIV="${SEC_BLOCK_PRIV:-yes}"      # Privilegierte User auf Kanaelen blocken
SEC_TLS="${SEC_TLS:-no}"                     # TLS-Key-Repository + Self-Signed-Cert
SEC_AMS="${SEC_AMS:-no}"                     # Advanced Message Security installieren
INST_WEB="${INST_WEB:-no}"                   # MQ Web Console installieren
ENABLE_AUTOSTART="${ENABLE_AUTOSTART:-yes}"  # systemd-Autostart einrichten

# Bequemlichkeits-Aliase (tail-/mqsc-/status-/... je QM, systemweit via profile.d)
ENABLE_ALIASES="${ENABLE_ALIASES:-yes}"

# Modus-Auswahl fuer --non-interactive (sonst per Hauptmenue): install|addqm|upgrade|feature|backup
MQ_MODE="${MQ_MODE:-install}"

# Upgrade-Optionen (Modus "upgrade")
UPGRADE_BACKUP="${UPGRADE_BACKUP:-yes}"      # /var/mqm vor dem Upgrade sichern
UPGRADE_BACKUP_DIR="${UPGRADE_BACKUP_DIR:-/var/mqm-backup-$(date +%Y%m%d-%H%M%S)}"

# Zusatzfeature-Optionen (Modus "feature": Nachinstallation auf bestehende Installation)
FEATURE_MQTT="${FEATURE_MQTT:-}"              # yes/no, leer = interaktiv abfragen
FEATURE_AMS="${FEATURE_AMS:-}"                # yes/no, leer = interaktiv abfragen
FEATURE_WEB="${FEATURE_WEB:-}"                # yes/no, leer = interaktiv abfragen
MQTT_QM="${MQTT_QM:-}"                        # Ziel-QM fuer MQTT/Telemetry, leer = abfragen
MQTT_SET_DEFXMITQ="${MQTT_SET_DEFXMITQ:-no}"  # SYSTEM.MQTT.TRANSMIT.QUEUE als DEFXMITQ setzen

# Backup-Optionen (Modus "backup")
BACKUP_DIR="${BACKUP_DIR:-/var/mqm-backups}"  # Zielverzeichnis fuer Backups
BACKUP_STOP_QM="${BACKUP_STOP_QM:-yes}"       # QM fuer konsistentes Daten-Backup anhalten
BACKUP_QMS="${BACKUP_QMS:-}"                  # leer/"all" = alle, sonst kommagetrennte Namen

# Restore-Optionen (Modus "restore")
RESTORE_SRC_DIR="${RESTORE_SRC_DIR:-$BACKUP_DIR}"  # Quellverzeichnis mit *-config-*.mqsc / *-data-*.tar.gz
RESTORE_MODE="${RESTORE_MODE:-config}"             # config = nur MQSC-Konfiguration | full = Daten-/Log-Archiv einspielen
RESTORE_QM="${RESTORE_QM:-}"                       # Ziel-QM/Backup-Basisname, leer = interaktiv waehlen
RESTORE_TS="${RESTORE_TS:-}"                       # Zeitstempel des gewuenschten Backups, leer = neuestes bzw. abfragen

# Modus "install": Verhalten, wenn auf dem Host bereits IBM-MQ-Pakete gefunden werden
# (leer = interaktiv fragen; yes = trotzdem installieren/downgraden, mit --allow-downgrades
# bzw. --oldpackage; no = abbrechen und auf addqm/upgrade/feature verweisen)
FORCE_REINSTALL="${FORCE_REINSTALL:-}"

# Modus "uninstall": vollstaendige Entfernung einer bestehenden Installation
UNINSTALL_CONFIRM="${UNINSTALL_CONFIRM:-}"        # leer = interaktiv fragen; yes/no fuer Automatisierung
UNINSTALL_BACKUP_FIRST="${UNINSTALL_BACKUP_FIRST:-yes}"  # vor der Entfernung Backup anbieten
UNINSTALL_REMOVE_USER="${UNINSTALL_REMOVE_USER:-no}"     # zusaetzlich mqm-User/-Gruppe + /var/mqm entfernen

# TLS-Defaults
TLS_CIPHER="${TLS_CIPHER:-ANY_TLS12_OR_HIGHER}"
TLS_CERT_DN="${TLS_CERT_DN:-CN=${MQ_QMGR_NAME},O=Example,C=DE}"

# Web-Console-Defaults
WEB_ADMIN_USER="${WEB_ADMIN_USER:-mqadmin}"  # Web-Admin (nur in mqweb, kein OS-Konto noetig)
WEB_ADMIN_PASS="${WEB_ADMIN_PASS:-}"         # leer = interaktiv abfragen / generieren
WEB_RO_USER="${WEB_RO_USER:-}"               # optionaler Nur-Lese-Web-Benutzer
WEB_RO_PASS="${WEB_RO_PASS:-}"
WEB_REMOTE="${WEB_REMOTE:-no}"               # Remote-Zugriff (alle Interfaces) erlauben
WEB_HTTPS_PORT="${WEB_HTTPS_PORT:-9443}"     # HTTPS-Port der Console
WEB_URL=""

MEDIA=""
NON_INTERACTIVE="no"
NO_TUI="no"          # --no-tui erzwingt reine Text-Prompts (kein whiptail/dialog)
UI_MODE="text"       # wird spaeter auf "tui" gesetzt, falls whiptail/dialog nutzbar ist
UI_TOOL=""           # "whiptail" oder "dialog"
LOGFILE="/var/log/ibmmq-install-$(date +%Y%m%d-%H%M%S).log"
WORKDIR=""

#-------------------------------------------------------------------------------
# 0b) TUI-Erkennung (whiptail/dialog) – graphische Konsolen-Oberflaeche
#-------------------------------------------------------------------------------
UI_BACKTITLE="IBM MQ 9.4.x / 10.x Installations-Script"

detect_tui() {
    [[ "$NO_TUI" == "yes" ]] && { UI_MODE="text"; return; }
    [[ "$NON_INTERACTIVE" == "yes" ]] && { UI_MODE="text"; return; }
    [[ -t 0 && -t 1 ]] || { UI_MODE="text"; return; }   # braucht ein echtes Terminal

    if command -v whiptail >/dev/null 2>&1; then
        UI_TOOL="whiptail"
    elif command -v dialog >/dev/null 2>&1; then
        UI_TOOL="dialog"
    else
        # Versuche whiptail unauffaellig nachzuinstallieren (best effort)
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
        [[ -n "$UI_TOOL" ]] && warn "$UI_TOOL gefunden, aber Funktionstest in diesem Terminal fehlgeschlagen (TERM='${TERM:-unset}') – falle auf Text-Modus zurueck."
        UI_TOOL=""
        UI_MODE="text"
    fi
}

# Prueft, ob sich das erkannte Tool im AKTUELLEN Terminal tatsaechlich fuer
# eine Vollbild-Anzeige nutzen laesst (nicht nur, ob das Binary existiert).
# Manche Umgebungen (TERM nicht gesetzt, sehr kleines Terminal, fehlende
# Terminfo-Eintraege, bestimmte serielle/eingebettete Konsolen) haben zwar
# whiptail/dialog installiert, koennen aber keine Vollbild-Dialoge rendern –
# ohne diesen Check wuerde das Script sich blind auf TUI verlassen und jede
# nachfolgende Abfrage koennte lautlos fehlschlagen oder leer bleiben.
tui_sanity_check() {
    local errfile rc
    errfile="$(mktemp /tmp/tui-check.XXXXXX 2>/dev/null)" || return 1
    "$UI_TOOL" --infobox "TUI-Test" 5 30 < /dev/tty > /dev/tty 2>"$errfile"
    rc=$?
    local haserr="no"
    [[ -s "$errfile" ]] && haserr="yes"
    rm -f "$errfile"
    [[ $rc -eq 0 && "$haserr" == "no" ]]
}

# Terminalgroesse fuer whiptail/dialog (mit sinnvollen Minimal-/Maximalwerten)
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
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Willkommen" \
        --msgbox "IBM MQ 9.4.x / 10.x Installations- und Hardening-Script\n\nUnterstuetzt: RHEL, SUSE Enterprise, Ubuntu, Raspberry Pi 4/5\n\nDie MQ-Version wird durch das mitgegebene --media bestimmt (9.4.x oder 10.0.x).\n\nIm Folgenden werden die Queue-Manager-Parameter, Security-Features und optionale Komponenten abgefragt.\n\nWeiter mit ENTER." \
        "$rows" "$cols" 3>&1 1>&2 2>&3 || true
}

ui_menu_intro() {
    # Kurzer Fortschritts-/Status-Screen zwischen Abschnitten
    [[ "$UI_MODE" == "tui" ]] || return 0
    local text="$1"
    local rows cols; read -r rows cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "$text" \
        --infobox "$text ..." 6 "$cols" || true
    sleep 1
}

ui_summary_box() {
    # Zeigt einen mehrzeiligen Text in einer Scroll-Box an (fuer Zusammenfassung)
    [[ "$UI_MODE" == "tui" ]] || return 0
    local title="$1" content="$2"
    local rows cols; read -r rows cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "$title" \
        --scrolltext --msgbox "$content" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
}

# Fuehrt einen (potenziell langsamen) Befehl im Hintergrund aus und zeigt dabei
# eine Fortschrittsanzeige, damit erkennbar bleibt, dass das Script noch laeuft
# und nicht haengt. TUI-Modus: echter whiptail-Fortschrittsbalken (Prozentzahl
# ist geschaetzt, da rpm/apt kein einfach auswertbares Live-Prozent liefern).
# Text-Modus: Sekunden-Heartbeat (Punkte). Gibt den echten Exit-Code des
# ausgefuehrten Befehls zurueck.
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
        ) | "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Bitte warten" \
                --gauge "$msg\n\n(laeuft im Hintergrund - Details im Logfile: $LOGFILE)" \
                12 "$cols" 0 2>/dev/null || true
    else
        echo -n "$msg "
        local elapsed=0
        while kill -0 "$pid" 2>/dev/null; do
            echo -n "."
            sleep 1
            elapsed=$((elapsed+1))
            # alle 30s einen Zeitstempel einstreuen, damit lange Laeufe nicht
            # wie eine endlose Punktreihe ohne Anhaltspunkt wirken
            if (( elapsed % 30 == 0 )); then
                echo -n " (${elapsed}s) "
            fi
        done
    fi

    wait "$pid"
    local rc=$?
    if [[ "$UI_MODE" != "tui" ]]; then
        if [[ $rc -eq 0 ]]; then echo " fertig."; else echo " FEHLER (Exit-Code $rc) – Logfile pruefen: $LOGFILE"; fi
    fi
    return $rc
}


# 1) Logging / Hilfsfunktionen
#-------------------------------------------------------------------------------
log()   { echo -e "[$(date '+%F %T')] $*" | tee -a "$LOGFILE"; }
info()  { log "INFO  $*"; }
warn()  { log "WARN  $*"; }
error() { log "ERROR $*" >&2; }
die()   { error "$*"; exit 1; }

# Wie die(), aber fuer Benutzer-Abbrueche (Cancel/Esc, oder explizites "Nein"
# auf eine Bestaetigungsfrage) statt echter Fehler: beendet NICHT das ganze
# Script, sondern signalisiert ueber den reservierten Exit-Code 99 der
# aeusseren Schleife (siehe run_main_flow ganz am Skriptende), zum Hauptmenue
# zurueckzukehren. Funktioniert unabhaengig davon, wie tief verschachtelt der
# Abbruch passiert, da die aeussere Schleife die gesamte Aktion in einer
# Subshell ausfuehrt und deren Exit-Code auswertet.
cancel_to_menu() {
    warn "${1:-Abbruch durch Benutzer.}"
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Sollte im Automatisierungsmodus nie erreicht werden (ask()/ask_yes_no()/
        # ask_secret() geben dort sofort den Default zurueck, ohne je ein
        # interaktives Dialogfeld zu zeigen) - sicherheitshalber trotzdem ein
        # echter Fehlerabbruch statt einer moeglichen Endlosschleife.
        die "Unerwarteter Abbruch im Automatisierungsmodus: ${1:-Abbruch durch Benutzer.}"
    fi
    info "Zurueck zum Hauptmenue ..."
    # WICHTIG: "exit 99" allein wuerde nur die INNERSTE Subshell beenden, die
    # z. B. jede Command-Substitution "X=\"\$(ask ...)\"" implizit erzeugt -
    # ask()/ask_yes_no()/ask_secret() werden aber praktisch ueberall genau so
    # aufgerufen. Ohne Signal wuerde der Aufrufer nur diesen Warn-/Info-Text
    # als (falschen) Rueckgabewert erhalten und einfach weiterlaufen, statt
    # zum Hauptmenue zurueckzukehren. Das Signal an die aeussere
    # run_main_flow-Subshell (siehe deren BASHPID in RUN_MAIN_FLOW_PID)
    # durchbricht JEDE Verschachtelungstiefe zuverlaessig.
    if [[ -n "${RUN_MAIN_FLOW_PID:-}" ]]; then
        kill -s USR1 "$RUN_MAIN_FLOW_PID" 2>/dev/null || true
    fi
    exit 99
}

# Technisch identischer Signal-Mechanismus wie cancel_to_menu(), aber fuer
# eine ERFOLGREICH abgeschlossene Aktion (z. B. Backup), nach der wieder das
# Hauptmenue gezeigt werden soll statt das Script zu beenden - daher keine
# "Abbruch"-Meldung, sondern optional ein neutraler Hinweistext.
return_to_menu() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Im Automatisierungsmodus gibt es kein interaktives Hauptmenue, zu dem
        # man zurueckkehren koennte - main_menu() wuerde sofort wieder denselben
        # MQ_MODE liefern und die Aktion erneut ausloesen (Endlosschleife).
        # Stattdessen normal beenden, wie es ein automatisierter Aufruf erwartet.
        exit 0
    fi
    [[ -n "${1:-}" ]] && info "$1"
    if [[ -n "${RUN_MAIN_FLOW_PID:-}" ]]; then
        kill -s USR1 "$RUN_MAIN_FLOW_PID" 2>/dev/null || true
    fi
    exit 99
}

# Rein informative Zwischenzeile (Abschnitts-Header, Hinweistexte) zwischen zwei
# interaktiven Abfragen: im TUI-Modus NUR ins Logfile schreiben, NICHT aufs
# Terminal (sonst kurzer Sprung auf die reine Konsole zwischen zwei
# whiptail-Dialogen, bis eine Taste gedrueckt wird). Im Text-Modus unveraendert
# wie info() auf Terminal UND Logfile.
narrate() {
    if [[ "$UI_MODE" == "tui" ]]; then
        echo "[$(date '+%F %T')] INFO  $*" >> "$LOGFILE" 2>/dev/null || true
    else
        info "$@"
    fi
}

on_error() {
    # $2 = Exit-Code des ausloesenden Befehls. 99 ist reserviert fuer
    # cancel_to_menu() (Benutzer-Abbruch, kein echter Fehler) - dafuer
    # keine Fehlermeldung ausgeben, auch wenn der Trap dabei technisch feuert
    # (bash loest den ERR-Trap fuer 'exit 99' selbst aus, unabhaengig davon,
    # ob zuvor per 'trap - ERR' deaktiviert wurde).
    local line="$1" rc="${2:-1}"
    [[ "$rc" == "99" ]] && return 0
    error "Abbruch in Zeile $line. Siehe Logfile: $LOGFILE"
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
Aufruf: sudo $0 --media <pfad> [Optionen]

  --media <pfad>        Pfad zur MQ-tar.gz ODER zum entpackten MQServer-Verzeichnis (Pflicht)
  --qmgr <name>         Name des ersten Queue-Managers (Default: $MQ_QMGR_NAME)
  --port <port>         Listener-Port des ersten QM (Default: $MQ_LISTENER_PORT)
  --non-interactive     Keine Rueckfragen, nutzt Defaults bzw. Umgebungsvariablen
  --no-tui              Erzwingt einfache Text-Prompts (kein whiptail/dialog-Menue)
  -h | --help           Diese Hilfe

Grafische Konsolen-Oberflaeche (TUI):
  Ist whiptail oder dialog verfuegbar und laeuft das Script in einem echten
  Terminal, werden Menues/Eingabefelder/Checkboxen (TUI) statt einfacher
  Text-Prompts angezeigt. Fehlt beides, installiert das Script bei Bedarf
  "whiptail" nach; schlaegt das fehl, faellt es automatisch auf Text-Prompts
  zurueck. Mit --no-tui laesst sich die TUI explizit abschalten.

Hauptmenue-Modi (interaktiv waehlbar, oder unbeaufsichtigt via MQ_MODE):
  install  Neuinstallation (Pakete installieren + Queue Manager einrichten)
  addqm    Weiteren Queue Manager zu bestehender Installation hinzufuegen
  backup   Backup eines oder aller Queue Manager (Konfig-Export via dmpmqcfg
           + Daten-/Log-Archiv), kein --media noetig, siehe BACKUP_*-Variablen
  restore  Queue Manager aus einem Backup wiederherstellen (Konfiguration per
           MQSC-Reimport, oder vollstaendig inkl. Daten-/Log-Archiv), kein
           --media noetig, Quellverzeichnis frei waehlbar, siehe RESTORE_*-Variablen
  upgrade  Bestehende Installation auf eine neuere Version upgraden
           (stoppt alle QMs, upgradet Pakete via rpm -Uvh/apt, startet QMs
           wieder -> automatische Migration; --media = Medien der NEUEN Version)
  feature  Zusatzfeature zu bestehender Installation hinzufuegen, z. B.
           MQTT/Telemetry (MQSeriesXRService) oder Advanced Message Security
  uninstall  IBM-MQ-Installation vollstaendig entfernen (alle Queue Manager,
           Pakete, systemd-Units, Aliase). Kein --media noetig. Optional
           zusaetzlich mqm-User/-Gruppe + /var/mqm via UNINSTALL_REMOVE_USER=yes.
           Siehe UNINSTALL_*-Variablen. UNWIDERRUFLICH - vorher Backup empfohlen.
  Beispiele:
     sudo MQ_MODE=backup  BACKUP_QMS=all ./install-ibmmq-9.4.sh --non-interactive
     sudo MQ_MODE=restore RESTORE_SRC_DIR=/pfad/zu/backups ./install-ibmmq-9.4.sh --non-interactive
     sudo MQ_MODE=upgrade ./install-ibmmq-9.4.sh --media <neue-medien> --non-interactive
     sudo MQ_MODE=uninstall UNINSTALL_CONFIRM=yes ./install-ibmmq-9.4.sh --non-interactive

Installationsmedium interaktiv waehlen:
  Wird --media nicht angegeben und ein Modus (install/upgrade/feature) benoetigt
  es, fragt das Script den Pfad zur tar.gz bzw. zum entpackten Verzeichnis direkt
  im Menuefluss ab (mit Wiederholung bei ungueltigem Pfad) - --media bleibt aber
  weiterhin die schnellste Variante fuer Automatisierung/Skripting.

Mehrere Queue Manager (1..x):
  Interaktiv wird die Anzahl abgefragt; je QM Name, Port und Kanal.
  Unbeaufsichtigt ueber die Variable MQ_QMGRS (Vorrang vor --qmgr/--port):
     MQ_QMGRS="NAME:PORT:CHANNEL,NAME:PORT:CHANNEL,..."
     Beispiel: MQ_QMGRS="QM1:1414:APP.SVRCONN,QM2:1415:APP.SVRCONN"
     (Port/Kanal optional; Port faengt sonst bei 1414 an, Kanal=$MQ_APP_CHANNEL)

Security-/Feature-Schalter ueber Umgebungsvariablen, z. B.:
     SEC_TLS=yes SEC_AMS=yes INST_WEB=yes  ./install-ibmmq-9.4.sh ...
EOF
}

ask() {
    # ask "Frage" "default"  -> gibt Antwort auf stdout
    local prompt="$1" default="$2" answer
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        echo "$default"; return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        answer="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Eingabe" \
            --inputbox "$prompt" 10 "$cols" "$default" 3>&1 1>&2 2>&3)"
        local rc=$?
        [[ $rc -ne 0 ]] && cancel_to_menu "Abbruch durch Benutzer (Eingabe abgebrochen)."
        echo "${answer:-$default}"
        return
    fi
    read -r -p "$prompt [$default]: " answer < /dev/tty || true
    echo "${answer:-$default}"
}

ask_yes_no() {
    # ask_yes_no "Frage" "yes|no" -> gibt yes/no zurueck
    local prompt="$1" default="$2" answer
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        echo "$default"; return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        local defbtn=(); [[ "$default" == "no" ]] && defbtn=(--defaultno)
        # WICHTIG: explizit gegen /dev/tty statt der Default-Deskriptoren, da
        # ask_yes_no IMMER als "X=$(ask_yes_no ...)" aufgerufen wird. Ohne die
        # /dev/tty-Umleitung wuerde whiptails eigene Bildschirmdarstellung
        # (Escape-Sequenzen) in die Variable eingefangen statt auf dem
        # Terminal zu erscheinen (--yesno nutzt bewusst NICHT den 3>&1 1>&2 2>&3
        # Trick, da es keinen Text liefert, nur den Exit-Code).
        # WICHTIG: whiptail liefert 0=Ja, 1=Nein, 255=ESC (Abbruch) - diese drei
        # Faelle muessen unterschieden werden ("|| rc=\$?" statt if/then/else,
        # sonst wuerde ESC faelschlich wie ein explizites "Nein" behandelt und
        # z. B. bei der Abschlussfrage nur zum Anpassen der Einstellungen fuehren
        # statt wirklich zum Hauptmenue abzubrechen).
        local rc=0
        "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Bestaetigung" \
            "${defbtn[@]}" --yesno "$prompt" 10 "$cols" < /dev/tty > /dev/tty 2>&1 || rc=$?
        case $rc in
            0) echo "yes" ;;
            1) echo "no" ;;
            *) cancel_to_menu "Abbruch durch Benutzer (ESC)." ;;
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
    # ask_secret "Prompt" "$aktueller_wert"
    # -> verdeckte Eingabe mit Wiederholung; Prompts gehen auf /dev/tty,
    #    nur das Passwort wird auf stdout zurueckgegeben.
    local prompt="$1" current="$2" p1 p2
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        if [[ -n "$current" ]]; then
            echo "$current"
        else
            # Kein Passwort vorgegeben -> sicheres Zufallspasswort erzeugen
            openssl rand -base64 15 2>/dev/null | tr -d '\n' || echo "Chg-Me-$(date +%s)"
        fi
        return
    fi
    if [[ "$UI_MODE" == "tui" ]]; then
        local rows cols; read -r rows cols <<< "$(ui_dims)"
        while true; do
            p1="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Passwort" \
                --passwordbox "$prompt" 10 "$cols" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
            p2="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Passwort" \
                --passwordbox "$prompt (Wiederholung)" 10 "$cols" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
            if [[ -z "$p1" ]]; then
                "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox "Passwort darf nicht leer sein." 8 60 < /dev/tty > /dev/tty 2>&1 || true
                continue
            fi
            if [[ "$p1" != "$p2" ]]; then
                "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox "Passwoerter stimmen nicht ueberein. Bitte erneut." 8 60 < /dev/tty > /dev/tty 2>&1 || true
                continue
            fi
            echo "$p1"; return
        done
    fi
    while true; do
        read -r -s -p "$prompt: " p1 < /dev/tty; echo > /dev/tty
        read -r -s -p "$prompt (Wiederholung): " p2 < /dev/tty; echo > /dev/tty
        if [[ "$p1" != "$p2" ]]; then
            echo "  -> Passwoerter stimmen nicht ueberein. Bitte erneut." > /dev/tty; continue
        fi
        if [[ -z "$p1" ]]; then
            echo "  -> Passwort darf nicht leer sein." > /dev/tty; continue
        fi
        echo "$p1"; return
    done
}

parse_qmgr_spec() {
    # Parst "NAME[:PORT[:CHANNEL]]" in die QMGR_*-Arrays.
    # PORT kann als PORT_START[-PORT_END] angegeben werden.
    # CHANNEL ist optional (Default: MQ_APP_CHANNEL).
    local spec="$1" entry idx=0 name port chan
    local OLDIFS="$IFS"; IFS=','
    for entry in $spec; do
        IFS="$OLDIFS"
        entry="$(echo "$entry" | tr -d '[:space:]')"
        [[ -z "$entry" ]] && { IFS=','; continue; }
        name="${entry%%:*}"
        local rest="${entry#*:}"
        if [[ "$rest" == "$entry" ]]; then
            # Nur Name angegeben
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
                # Port-Bereich angegeben -> sequenziell auffuellen
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
    [[ ${#QMGR_NAMES[@]} -ge 1 ]] || die "MQ_QMGRS konnte nicht geparst werden: '$spec'"
}

#-------------------------------------------------------------------------------
# 2) Argument-Parsing
#-------------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --media)            MEDIA="$2"; shift 2 ;;
        --qmgr)             MQ_QMGR_NAME="$2"; shift 2 ;;
        --port)             MQ_LISTENER_PORT="$2"; shift 2 ;;
        --non-interactive)  NON_INTERACTIVE="yes"; shift ;;
        --no-tui)           NO_TUI="yes"; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  die "Unbekannte Option: $1 (siehe --help)" ;;
    esac
done

#-------------------------------------------------------------------------------
# 3) Vorbedingungen
#-------------------------------------------------------------------------------
[[ $EUID -eq 0 ]] || die "Bitte als root bzw. mit sudo ausfuehren."
touch "$LOGFILE" 2>/dev/null || LOGFILE="/tmp/$(basename "$LOGFILE")"
info "Logfile: $LOGFILE"
info "IBM MQ 9.4.x / 10.x Installations-Script gestartet."

#-------------------------------------------------------------------------------
# 4) OS- und Architektur-Erkennung
#-------------------------------------------------------------------------------
detect_platform() {
    [[ -r /etc/os-release ]] || die "Kann /etc/os-release nicht lesen."
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
        *) die "Nicht unterstuetzte Architektur: $ARCH" ;;
    esac

    # Paketformat bestimmen
    if [[ "$OS_ID" =~ ^(rhel|centos|rocky|almalinux|fedora)$ ]] || [[ "$OS_LIKE" =~ rhel ]]; then
        PKG_FORMAT="rpm"; PKG_FAMILY="rhel"
    elif [[ "$OS_ID" =~ ^(sles|sled|opensuse.*|suse)$ ]] || [[ "$OS_LIKE" =~ suse ]]; then
        PKG_FORMAT="rpm"; PKG_FAMILY="suse"
    elif [[ "$OS_ID" =~ ^(ubuntu|debian|raspbian)$ ]] || [[ "$OS_LIKE" =~ debian ]]; then
        PKG_FORMAT="deb"; PKG_FAMILY="debian"
    else
        die "Nicht unterstuetzte Distribution: $OS_ID ($OS_LIKE)"
    fi

    IS_RPI="no"
    if grep -qi "raspberry" /proc/cpuinfo 2>/dev/null || \
       grep -qi "raspberry" /sys/firmware/devicetree/base/model 2>/dev/null; then
        IS_RPI="yes"
    fi

    info "Distribution : $OS_ID $OS_VERSION  (Familie: $PKG_FAMILY, Format: $PKG_FORMAT)"
    info "Architektur  : $ARCH  (Klasse: $ARCH_CLASS)"
    info "Raspberry Pi : $IS_RPI"

    # Warnhinweise zu Raspberry Pi
    if [[ "$IS_RPI" == "yes" && "$ARCH_CLASS" == "arm32" ]]; then
        warn "32-Bit Raspberry Pi erkannt. IBM MQ ARM32 ist nur 'as-is' (ohne offiziellen Support)."
        warn "Empfehlung: 64-Bit OS (Raspberry Pi OS 64-bit oder Ubuntu ARM64) fuer den ARM64-Build verwenden."
        if [[ "$(ask_yes_no 'Trotzdem fortfahren?' 'no')" != "yes" ]]; then
            die "Abbruch durch Benutzer (32-Bit RPi)."
        fi
    fi
    if [[ "$ARCH_CLASS" == "arm64" ]]; then
        info "ARM64-Build wird verwendet (offiziell ab IBM MQ 9.4.1 fuer Ubuntu/RPi 64-bit verfuegbar, in 10.0.x fortgefuehrt)."
    fi
}
detect_platform

#-------------------------------------------------------------------------------
# 5) Paket-Voraussetzungen installieren (tar, libs)
#-------------------------------------------------------------------------------
install_prereqs() {
    info "Installiere Basis-Voraussetzungen ..."
    case "$PKG_FAMILY" in
        rhel)
            local mgr="dnf"; command -v dnf >/dev/null 2>&1 || mgr="yum"
            $mgr -y install tar bash coreutils which findutils >>"$LOGFILE" 2>&1 || \
                warn "Voraussetzungen konnten nicht vollstaendig installiert werden (ggf. kein Repo)."
            ;;
        suse)
            zypper --non-interactive install tar bash coreutils which findutils >>"$LOGFILE" 2>&1 || \
                warn "Voraussetzungen konnten nicht vollstaendig installiert werden."
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update >>"$LOGFILE" 2>&1 || warn "apt-get update fehlgeschlagen."
            apt-get -y install tar bash coreutils findutils >>"$LOGFILE" 2>&1 || \
                warn "Voraussetzungen konnten nicht vollstaendig installiert werden."
            ;;
    esac
}
install_prereqs

#-------------------------------------------------------------------------------
# 5b) TUI aktivieren (whiptail/dialog) und Willkommensbildschirm anzeigen
#-------------------------------------------------------------------------------
detect_tui
if [[ "$UI_MODE" == "tui" ]]; then
    info "Grafische Konsolen-Oberflaeche (TUI) aktiv: $UI_TOOL"
else
    info "Text-Modus aktiv (kein whiptail/dialog verfuegbar oder --no-tui/--non-interactive gesetzt)."
fi
ui_welcome

#-------------------------------------------------------------------------------
# 5c) Hauptmenue – Betriebsmodus waehlen
#-------------------------------------------------------------------------------
MODE="install"   # install | addqm | upgrade | feature | backup | restore | uninstall | objects | tls

mq_is_installed() {
    [[ -x "$MQ_INSTALL_PATH/bin/setmqenv" ]]
}

show_status_menu() {
    echo
    info "==== Status vorhandener Queue Manager ===="
    if ! id mqm >/dev/null 2>&1; then
        warn "Benutzer 'mqm' existiert nicht – IBM MQ scheint auf diesem Host nicht installiert zu sein."
        return 0
    fi
    source_mqenv 2>/dev/null || true

    while true; do
        # dspmq mit Status UND zugeordneter Installation abfragen (zwei -o
        # Parameter lassen sich kombinieren) - wichtig, um "verwaiste" QMs
        # (einer nicht mehr installierten Version zugeordnet) sofort zu sehen.
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
                qm_status+=("${status:-unbekannt}")
                qm_inst+=("${inst:-unbekannt}")
            done <<< "$raw"
        fi

        local display
        if [[ ${#qm_names[@]} -eq 0 ]]; then
            display="Keine Queue Manager auf diesem Host gefunden."
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
            "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Queue-Manager-Status" \
                --msgbox "$display" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
        fi

        [[ ${#qm_names[@]} -eq 0 ]] && return 0

        if [[ "$(ask_yes_no 'Einen Queue Manager starten oder stoppen?' 'no')" != "yes" ]]; then
            return 0
        fi

        # ---- Queue Manager auswaehlen ----
        local sel_qm=""
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local items=()
            for i in "${!qm_names[@]}"; do
                items+=("${qm_names[$i]}" "${qm_status[$i]} / ${qm_inst[$i]}")
            done
            sel_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Queue Manager waehlen" \
                --menu "Welchen Queue Manager verwalten?" "$rows" "$cols" "${#qm_names[@]}" \
                "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        else
            for i in "${!qm_names[@]}"; do
                echo "  $((i+1))) ${qm_names[$i]}  (${qm_status[$i]}, ${qm_inst[$i]})"
            done
            local choice
            read -r -p "Nummer waehlen: " choice < /dev/tty || true
            if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#qm_names[@]}" ]]; then
                sel_qm="${qm_names[$((choice-1))]}"
            fi
        fi
        [[ -n "$sel_qm" ]] || cancel_to_menu "Kein Queue Manager ausgewaehlt."

        # ---- Aktion auswaehlen ----
        local action="start"
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            action="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Aktion fuer $sel_qm" \
                --menu "Aktion fuer '$sel_qm' waehlen:" "$rows" "$cols" 2 \
                "start" "Starten" \
                "stop"  "Stoppen" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        else
            echo "  1) Starten"
            echo "  2) Stoppen"
            local achoice
            read -r -p "Aktion [1]: " achoice < /dev/tty || true
            [[ "$achoice" == "2" ]] && action="stop"
        fi

        if [[ "$action" == "start" ]]; then
            manage_start_qmgr "$sel_qm"
        else
            info "Stoppe '$sel_qm' (endmqm -w, kontrolliert) ..."
            if su -s /bin/bash mqm -c "endmqm -w '$sel_qm'" >>"$LOGFILE" 2>&1; then
                info "'$sel_qm' gestoppt."
            else
                warn "'$sel_qm' konnte nicht kontrolliert gestoppt werden (endmqm -w)."
                if [[ "$(ask_yes_no "Sofortigen Stopp (endmqm -i) fuer '$sel_qm' erzwingen?" 'no')" == "yes" ]]; then
                    su -s /bin/bash mqm -c "endmqm -i '$sel_qm'" >>"$LOGFILE" 2>&1 \
                        && info "'$sel_qm' per 'endmqm -i' gestoppt." \
                        || warn "'$sel_qm' konnte auch mit 'endmqm -i' nicht gestoppt werden. Logfile pruefen."
                fi
            fi
        fi
        # Schleife: Statusanzeige aktualisiert erneut anzeigen
    done
}

# "Weiche" Variante von start_qmgr_robust fuer die interaktive Status-/
# Verwaltungsanzeige: warnt bei Fehlschlag, statt das ganze Script per die()
# zu beenden (hier soll ein fehlgeschlagener Start nicht die Menue-Sitzung
# abbrechen, der Benutzer soll einfach weiterarbeiten koennen).
manage_start_qmgr() {
    local qm="$1"
    info "Starte '$qm' ..."
    local out rc=0
    out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    if [[ $rc -eq 0 ]]; then
        info "'$qm' gestartet."
        return 0
    fi
    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        warn "'$qm' ist einer anderen (evtl. nicht mehr installierten) MQ-Installation zugeordnet."
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]] && [[ "$(ask_yes_no "Versuchen, '$qm' der aktuellen Installation '$inst_name' zuzuordnen (setmqm) und erneut zu starten?" 'yes')" == "yes" ]]; then
            info "Ordne '$qm' der Installation '$inst_name' zu (setmqm) ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                rc=0
                out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
                echo "$out" >> "$LOGFILE"
                if [[ $rc -eq 0 ]]; then
                    info "'$qm' nach Neuzuordnung gestartet."
                    return 0
                fi
            fi
            warn "setmqm/erneuter Start fehlgeschlagen."
        fi
    fi
    warn "'$qm' konnte nicht gestartet werden. Logfile pruefen: $LOGFILE"
    return 1
}

show_aliases_menu() {
    echo
    info "==== Bequemlichkeits-Aliase ===="
    local out=""

    local afile="/etc/profile.d/mqm-aliases.sh"
    if [[ -f "$afile" ]]; then
        local anames
        anames="$(grep '^alias ' "$afile" 2>/dev/null | sed "s/^alias \([^=]*\)=.*/\1/" | tr '\n' ' ')"
        out+="Verfuegbare Aliase (aus $afile):"$'\n'"  ${anames:-<keine gefunden>}"
        out+=$'\n\n'"Wirksam nach neuer Anmeldung (SSH-Login bzw. 'sudo su -')."
        out+=$'\n'"Volle Befehle ansehen: cat $afile"
    else
        out+="Keine Aliase angelegt (Datei '$afile' existiert nicht)."
    fi

    echo "$out" | tee -a "$LOGFILE"
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Aliase" \
            --msgbox "$out" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
    fi
    return 0
}

main_menu() {
    # Automatisierung (--non-interactive) ueberspringt das Menue.
    # MQ_MODE erlaubt Automatisierung auch fuer addqm/upgrade/feature (Default: install).
    [[ "$NON_INTERACTIVE" == "yes" ]] && { MODE="$MQ_MODE"; return; }

    local installed="nein"

    while true; do
        mq_is_installed && installed="ja" || installed="nein"

        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local choice
            choice="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Hauptmenue" \
                --cancel-button "Beenden" \
                --menu "IBM MQ bereits installiert: $installed\n\nBitte Aktion waehlen:" \
                "$rows" "$cols" 12 \
                "1" "Neuinstallation (Pakete installieren + Queue Manager einrichten)" \
                "2" "Weiteren Queue Manager zu bestehender Installation hinzufuegen" \
                "3" "Backup eines oder aller Queue Manager erstellen" \
                "4" "Queue Manager aus einem Backup wiederherstellen (Restore)" \
                "5" "Bestehende Installation auf neuere Version upgraden" \
                "6" "Zusatzfeature nachinstallieren (z. B. MQTT/Telemetry, AMS, Web)" \
                "7" "IBM-MQ-Installation vollstaendig entfernen (Deinstallation)" \
                "8" "Objekte fuer Queue Manager erstellen (Kanaele, Listener)" \
                "9" "SSL/TLS-Verwaltung (Zertifikate, Trust-Chain)" \
                "10" "Status vorhandener Queue Manager anzeigen" \
                "11" "Alias-Uebersicht anzeigen" \
                "12" "Beenden" \
                3>&1 1>&2 2>&3)" || { info "Abbruch durch Benutzer."; exit 0; }
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
                *) info "Beendet."; exit 0 ;;
            esac
        else
            echo
            echo "==================================================================="
            echo " IBM MQ 9.4.x / 10.x Installations-Script – Hauptmenue"
            echo " (IBM MQ bereits installiert: $installed)"
            echo "==================================================================="
            echo "  1) Neuinstallation (Pakete installieren + Queue Manager einrichten)"
            echo "  2) Weiteren Queue Manager zu bestehender Installation hinzufuegen"
            echo "  3) Backup eines oder aller Queue Manager erstellen"
            echo "  4) Queue Manager aus einem Backup wiederherstellen (Restore)"
            echo "  5) Bestehende Installation auf neuere Version upgraden"
            echo "  6) Zusatzfeature nachinstallieren (z. B. MQTT/Telemetry, AMS, Web)"
            echo "  7) IBM-MQ-Installation vollstaendig entfernen (Deinstallation)"
            echo "  8) Objekte fuer Queue Manager erstellen (Kanaele, Listener)"
            echo "  9) SSL/TLS-Verwaltung (Zertifikate, Trust-Chain)"
            echo " 10) Status vorhandener Queue Manager anzeigen"
            echo " 11) Alias-Uebersicht anzeigen"
            echo " 12) Beenden"
            echo "==================================================================="
            local choice
            read -r -p "Auswahl [1]: " choice < /dev/tty || true
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
                12) info "Beendet."; exit 0 ;;
                *) warn "Ungueltige Auswahl, starte Neuinstallation."; MODE="install" ;;
            esac
        fi
        break
    done

    if [[ "$MODE" =~ ^(addqm|upgrade|feature|backup|restore|uninstall|objects|tls)$ ]] && ! mq_is_installed; then
        warn "Keine bestehende IBM-MQ-Installation unter '$MQ_INSTALL_PATH' gefunden."
        if [[ "$UI_MODE" == "tui" ]]; then
            "$UI_TOOL" --backtitle "$UI_BACKTITLE" --msgbox \
                "Keine bestehende IBM-MQ-Installation gefunden.\nEs wird stattdessen eine Neuinstallation durchgefuehrt." 8 70 || true
        fi
        info "Falle zurueck auf Neuinstallation."
        MODE="install"
    fi

    local _tty_stdin="nein" _tty_stdout="nein"
    [[ -t 0 ]] && _tty_stdin="ja"
    [[ -t 1 ]] && _tty_stdout="ja"
    info "Gewaehlter Modus: $MODE (UI_MODE=$UI_MODE, UI_TOOL=${UI_TOOL:-keins}, TTY: stdin=$_tty_stdin stdout=$_tty_stdout)"
}

#-------------------------------------------------------------------------------
# 5e) Wiederverwendbare Installationsfunktionen (frueh definiert, damit sie von
#     perform_upgrade()/perform_feature_install() UND vom normalen Install-Fluss
#     weiter unten genutzt werden koennen)
#-------------------------------------------------------------------------------
prepare_media() {
    info "Bereite Installationsmedien vor ..."
    if [[ -d "$MEDIA" ]]; then
        # Verzeichnis: entweder bereits entpackte Medien (MQServer-Ordner
        # bis zu 5 Ebenen tief, gross-/kleinschreibungsunabhaengig), oder ein
        # Verzeichnis, das noch eine ungeoeffnete tar.gz enthaelt.
        if [[ -f "$MEDIA/mqlicense.sh" ]]; then
            MQ_SRC="$MEDIA"
        elif [[ -f "$MEDIA/MQServer/mqlicense.sh" ]]; then
            MQ_SRC="$MEDIA/MQServer"
        else
            MQ_SRC="$(find "$MEDIA" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
            if [[ -z "$MQ_SRC" ]]; then
                # Keine entpackten Medien gefunden - liegt evtl. eine
                # ungeoeffnete tar.gz direkt in diesem Verzeichnis?
                local found_tars found_tar tar_count
                found_tars="$(find "$MEDIA" -maxdepth 2 -iname '*.tar.gz' 2>/dev/null | sort)"
                tar_count="$(echo "$found_tars" | grep -c . || true)"
                if [[ "$tar_count" -ge 1 ]]; then
                    found_tar="$(echo "$found_tars" | head -n1)"
                    if [[ "$tar_count" -gt 1 ]]; then
                        warn "Mehrere .tar.gz-Dateien unter '$MEDIA' gefunden, verwende die erste (alphabetisch):"
                        echo "$found_tars" | sed 's/^/  /' | tee -a "$LOGFILE"
                    fi
                    info "Keine entpackten Medien gefunden, aber ungeoeffnetes Archiv erkannt: $found_tar"
                    WORKDIR="$(mktemp -d /tmp/ibmmq.XXXXXX)"
                    narrate "Entpacke $found_tar nach $WORKDIR (GNU tar) ..."
                    run_with_progress "Entpacke Installationsmedium ..." tar -xzf "$found_tar" -C "$WORKDIR" \
                        || die "Entpacken von '$found_tar' fehlgeschlagen. Logfile pruefen: $LOGFILE"
                    MQ_SRC="$(find "$WORKDIR" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
                fi
            fi
        fi
    else
        # MEDIA ist eine Datei -> direkt als tar.gz behandeln (GNU tar zwingend erforderlich)
        WORKDIR="$(mktemp -d /tmp/ibmmq.XXXXXX)"
        narrate "Entpacke $MEDIA nach $WORKDIR (GNU tar) ..."
        run_with_progress "Entpacke Installationsmedium ..." tar -xzf "$MEDIA" -C "$WORKDIR" \
            || die "Entpacken des Installationsmediums fehlgeschlagen. Logfile pruefen: $LOGFILE"
        MQ_SRC="$(find "$WORKDIR" -maxdepth 5 -iname mqlicense.sh -printf '%h\n' 2>/dev/null | head -n1)"
    fi

    if [[ -z "${MQ_SRC:-}" || ! -f "$MQ_SRC/mqlicense.sh" ]]; then
        warn "Konnte mqlicense.sh unter '$MEDIA' nicht finden (bis zu 5 Verzeichnisebenen durchsucht, auch nach *.tar.gz gesucht)."
        warn "Tatsaechlicher Inhalt von '$MEDIA' (2 Ebenen tief):"
        find "$MEDIA" -maxdepth 2 2>/dev/null | sed 's/^/  /' | tee -a "$LOGFILE" || true
        die "mqlicense.sh nicht gefunden. Bitte --media entweder direkt auf die .tar.gz-Datei zeigen lassen (z. B. --media /install/MQServer-9.4.0.x-Linux.tar.gz) oder auf das bereits entpackte Verzeichnis mit mqlicense.sh – siehe Verzeichnisinhalt oben."
    fi
    info "Installationsquelle: $MQ_SRC"
}

accept_license() {
    info "Akzeptiere IBM MQ Lizenzvereinbarung ..."
    ( cd "$MQ_SRC" && ./mqlicense.sh -accept >>"$LOGFILE" 2>&1 ) || \
        die "Lizenzakzeptanz fehlgeschlagen. Logfile pruefen."
    info "Lizenz akzeptiert."
}

# Bindet IBMs setmqenv per 'source' ein, um PATH/Umgebung fuer die MQ-Befehle
# (dspmqver, crtmqm, runmqsc, ...) im aktuellen Shell-Prozess verfuegbar zu
# machen. WICHTIG: setmqenv ist nicht fuer 'set -u' geschrieben (referenziert
# z. B. $ZSH_EVAL_CONTEXT ungeschuetzt fuer eine Shell-Erkennung). Da wir es
# per 'source' einbinden, laeuft es im selben Shell-Prozess und wuerde unser
# 'set -u' erben -> sofortiger Abbruch mit "unbound variable". Waehrend des
# Sourcens daher voruebergehend lockern und danach wiederherstellen.
source_mqenv() {
    local rc=0
    set +u
    # shellcheck disable=SC1090
    . "$MQ_INSTALL_PATH/bin/setmqenv" -s || rc=$?
    set -u
    return $rc
}

post_install_setup() {
    info "Konfiguriere Installation ..."
    if [[ -x "$MQ_INSTALL_PATH/bin/setmqinst" ]]; then
        # Nur als Primaerinstallation setzen, wenn noch keine existiert
        if ! "$MQ_INSTALL_PATH/bin/dspmqinst" 2>/dev/null | grep -qi "Primary:.*Yes"; then
            "$MQ_INSTALL_PATH/bin/setmqinst" -i -p "$MQ_INSTALL_PATH" >>"$LOGFILE" 2>&1 || \
                warn "setmqinst (Primaerinstallation) fehlgeschlagen – ggf. existiert bereits eine."
        fi
    fi
    # MQ-Umgebung systemweit verfuegbar machen
    cat > /etc/profile.d/mqenv.sh <<EOF
# IBM MQ Umgebung
if [ -f "$MQ_INSTALL_PATH/bin/setmqenv" ]; then
    # set -u ggf. lockern: setmqenv referenziert \$ZSH_EVAL_CONTEXT ungeschuetzt
    case "\$-" in *u*) __mqenv_had_u=1; set +u ;; *) __mqenv_had_u=0 ;; esac
    . "$MQ_INSTALL_PATH/bin/setmqenv" -s >/dev/null 2>&1
    [ "\$__mqenv_had_u" = "1" ] && set -u
    unset __mqenv_had_u
fi
EOF
    source_mqenv
    info "IBM MQ Version:"
    dspmqver | tee -a "$LOGFILE"
    MQ_INSTALLED_VERSION="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
}

# Startet einen Queue Manager per strmqm. Erkennt den Fall, dass der QM einer
# anderen (evtl. nicht mehr installierten) MQ-Installation zugeordnet ist
# (AMQ7204E - passiert typischerweise, wenn frueher eine andere MQ-Version
# installiert war und der QM damit erstellt/gestartet wurde). In diesem Fall
# wird - nach Bestaetigung - versucht, den QM per 'setmqm' der aktuellen
# Installation zuzuordnen und danach erneut zu starten, statt nur mit einer
# generischen Fehlermeldung abzubrechen.
start_qmgr_robust() {
    local qm="$1"
    local out rc=0
    out="$(su -s /bin/bash mqm -c "strmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    [[ $rc -eq 0 ]] && return 0

    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        warn "Queue Manager '$qm' ist einer anderen (evtl. nicht mehr installierten) MQ-Installation zugeordnet."
        warn "Das passiert typischerweise, wenn frueher eine andere MQ-Version installiert war und dieser"
        warn "Queue Manager damit erstellt/zuletzt gestartet wurde."
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]] && [[ "$(ask_yes_no "Versuchen, '$qm' der aktuellen Installation '$inst_name' zuzuordnen (setmqm) und erneut zu starten?" 'yes')" == "yes" ]]; then
            info "Ordne '$qm' der Installation '$inst_name' zu (setmqm) ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                info "Starte '$qm' erneut ..."
                if su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1; then
                    info "'$qm' erfolgreich gestartet nach Neuzuordnung."
                    return 0
                fi
            fi
            warn "setmqm/erneuter Start fehlgeschlagen."
        fi
        die "'$qm' ist einer anderen Installation zugeordnet und konnte nicht gestartet werden. Manuelle Optionen: (1) 'setmqm -m $qm -i <Installationsname>' zum Zuordnen zur aktuellen Installation, dann 'strmqm $qm'. (2) Falls '$qm' nur Testdaten enthaelt: Daten unter /var/mqm/qmgrs/$qm und /var/mqm/log/$qm gemaess IBM-Dokumentation entfernen (dltmqm bzw. manuell) und den QM ueber das Hauptmenue neu anlegen."
    fi
    die "strmqm fuer '$qm' fehlgeschlagen. Logfile pruefen: $LOGFILE"
}

# Stoppt (falls noetig) und loescht einen Queue Manager sauber (dltmqm).
# Erkennt denselben "andere Installation"-Fall wie start_qmgr_robust und
# versucht in dem Fall vorher setmqm, damit dltmqm nicht grundlos fehlschlaegt.
# Gibt bei Fehlschlag NICHT die ganze Deinstallation auf (warn statt die),
# da moeglichst viele QMs entfernt werden sollen, auch wenn einer haengt.
delete_qmgr_robust() {
    local qm="$1"
    su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 || true

    local out rc=0
    out="$(su -s /bin/bash mqm -c "dltmqm '$qm'" 2>&1)" || rc=$?
    echo "$out" >> "$LOGFILE"
    if [[ $rc -eq 0 ]]; then
        info "Queue Manager '$qm' geloescht."
        return 0
    fi

    if echo "$out" | grep -qi "AMQ7204E\|previously been started by a newer\|cannot be started or otherwise"; then
        local inst_name
        inst_name="$(dspmqver 2>/dev/null | awk -F': *' '/^InstName/{print $2; exit}')" || true
        if [[ -n "$inst_name" ]]; then
            warn "'$qm' ist einer anderen Installation zugeordnet - versuche Neuzuordnung (setmqm) vor dem Loeschen ..."
            if setmqm -m "$qm" -i "$inst_name" >>"$LOGFILE" 2>&1; then
                rc=0
                out="$(su -s /bin/bash mqm -c "dltmqm '$qm'" 2>&1)" || rc=$?
                echo "$out" >> "$LOGFILE"
                if [[ $rc -eq 0 ]]; then
                    info "Queue Manager '$qm' nach Neuzuordnung geloescht."
                    return 0
                fi
            fi
        fi
    fi

    warn "'$qm' konnte nicht per dltmqm entfernt werden (Logfile pruefen). Entferne Verzeichnisse manuell ..."
    rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
        && info "Verzeichnisse von '$qm' manuell entfernt (mqs.ini-Eintrag bleibt ggf. bestehen)." \
        || warn "Manuelles Entfernen der Verzeichnisse von '$qm' teilweise fehlgeschlagen."
    return 1
}

# Namen aller auf diesem Host bekannten Queue Manager (ein Name pro Zeile, leer wenn keine/kein mqm-User)
get_all_qm_names() {
    id mqm >/dev/null 2>&1 || return 0
    su -s /bin/bash mqm -c "dspmq" 2>/dev/null | sed -n "s/.*QMNAME(\([^)]*\)).*/\1/p" || true
}

# Gibt "yes" zurueck, wenn auf diesem Host bereits IBM-MQ-Pakete installiert
# sind (unabhaengig von der Version). Wichtig fuer den Modus "install", der
# fuer einen frischen Host gedacht ist: apt/rpm wuerden sonst ggf. vorhandene
# Pakete stillschweigend downgraden oder sogar entfernen, wenn deren Version
# oder Auswahl nicht zu diesem Lauf passt.
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

# Ermittelt die aktuell installierte MQ-Version anhand des Runtime-Pakets
# (z. B. "9.4.4.0"). Leer, falls nicht installiert/nicht ermittelbar.
get_installed_mq_version() {
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        rpm -q --qf '%{VERSION}\n' MQSeriesRuntime 2>/dev/null | head -n1
    else
        dpkg-query -W -f='${Version}\n' ibmmq-runtime 2>/dev/null | head -n1
    fi
}

# Ermittelt die MQ-Version, die in den bereitgestellten Installationsmedien
# enthalten ist, anhand des Dateinamens des Runtime-Pakets in $MQ_SRC
# (z. B. "ibmmq-runtime_9.4.1.0_amd64.deb" -> "9.4.1.0"). Leer, falls nicht ermittelbar.
get_media_mq_version() {
    local f
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        f="$(find "$MQ_SRC" -maxdepth 1 -name 'MQSeriesRuntime-*.rpm' 2>/dev/null | head -n1)"
    else
        f="$(find "$MQ_SRC" -maxdepth 1 -name 'ibmmq-runtime_*.deb' 2>/dev/null | head -n1)"
    fi
    [[ -n "$f" ]] && basename "$f" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

# Vergleicht Medien-Version gegen installierte Version. Gibt "yes" zurueck,
# wenn die Medien eine NIEDRIGERE Version waeren als die installierte (also
# ein echtes Downgrade, das IBM MQ grundsaetzlich NICHT unterstuetzt und das
# das Paket-Installationsskript selbst hart verweigert - unabhaengig von
# apt/rpm-Optionen wie --allow-downgrades). "no", wenn gleich, neuer, oder
# nicht ermittelbar (dann lieber durchlassen und die eigentliche
# Paketinstallation entscheiden lassen, als faelschlich zu blockieren).
would_be_real_downgrade() {
    local installed_ver="$1" media_ver="$2"
    [[ -n "$installed_ver" && -n "$media_ver" ]] || { echo "no"; return; }
    if [[ "$PKG_FORMAT" == "deb" ]] && command -v dpkg >/dev/null 2>&1; then
        if dpkg --compare-versions "$media_ver" lt "$installed_ver" 2>/dev/null; then
            echo "yes"; return
        fi
    else
        # Einfacher, verlustfreier Versionsvergleich ueber 'sort -V' (funktioniert
        # fuer die uebliche x.y.z.w-Form gleichermassen fuer rpm wie deb).
        local lower
        lower="$(printf '%s\n%s\n' "$media_ver" "$installed_ver" | sort -V | head -n1)"
        if [[ "$lower" == "$media_ver" && "$media_ver" != "$installed_ver" ]]; then
            echo "yes"; return
        fi
    fi
    echo "no"
}

# Fragt (falls MEDIA leer ist und interaktiv) nach dem Installationsmedium und
# validiert den Pfad; wiederholt die Abfrage bei ungueltiger Eingabe.
ensure_media_path() {
    local mode_label="$1"
    if [[ -z "$MEDIA" ]]; then
        [[ "$NON_INTERACTIVE" == "yes" ]] && { usage; die "--media ist erforderlich fuer Modus '$mode_label'."; }
        local prompt="Pfad zur MQ-tar.gz ODER zum entpackten MQServer-Verzeichnis"
        while true; do
            MEDIA="$(ask "$prompt" "$MEDIA")"
            if [[ -z "$MEDIA" ]]; then
                narrate "Kein Pfad angegeben - erneute Abfrage."
                prompt="Bitte einen Pfad angeben. Pfad zur MQ-tar.gz ODER zum entpackten MQServer-Verzeichnis"
                continue
            fi
            if [[ ! -e "$MEDIA" ]]; then
                narrate "Pfad '$MEDIA' existiert nicht - erneute Abfrage."
                prompt="Pfad existiert nicht, bitte erneut versuchen. Pfad zur MQ-tar.gz ODER zum entpackten MQServer-Verzeichnis"
                MEDIA=""
                continue
            fi
            break
        done
    fi
    [[ -n "$MEDIA" ]] || { usage; die "--media ist erforderlich fuer Modus '$mode_label'."; }
    [[ -e "$MEDIA" ]] || die "Medienpfad existiert nicht: $MEDIA"
}

#-------------------------------------------------------------------------------
# 5f) Upgrade einer bestehenden Installation auf eine neuere Version
#-------------------------------------------------------------------------------
upgrade_rpm_packages() {
    narrate "Ermittle installierte RPM-Komponenten fuer das Upgrade ..."
    local installed_names; installed_names="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep '^MQSeries' || true)"
    [[ -n "$installed_names" ]] || die "Keine installierten MQSeries-RPM-Pakete gefunden – Upgrade nicht moeglich."
    local files=() name f
    for name in $installed_names; do
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${name}-*.rpm" | head -n1 || true)"
        if [[ -n "$f" ]]; then
            files+=("$f")
        else
            warn "Kein Upgrade-Paket fuer '$name' in den Medien gefunden – wird uebersprungen."
        fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "Keine passenden Upgrade-Pakete in den Medien gefunden."
    narrate "Upgrade von ${#files[@]} Paketen via 'rpm -Uvh' (Upgrade, NICHT -ivh) ..."
    run_with_progress "Upgrade von ${#files[@]} RPM-Paket(en) (kann 1-2 Minuten dauern) ..." \
        rpm -Uvh "${files[@]}" || die "RPM-Upgrade fehlgeschlagen. Logfile pruefen: $LOGFILE"
    info "RPM-Pakete erfolgreich aktualisiert."
}

upgrade_deb_packages() {
    narrate "Ermittle installierte DEB-Komponenten fuer das Upgrade ..."
    local installed_names; installed_names="$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep '^ibmmq-' || true)"
    [[ -n "$installed_names" ]] || die "Keine installierten ibmmq-*-Pakete gefunden – Upgrade nicht moeglich."
    local files=() name f
    for name in $installed_names; do
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${name}_*.deb" | head -n1 || true)"
        if [[ -n "$f" ]]; then
            files+=("$f")
        else
            warn "Kein Upgrade-Paket fuer '$name' in den Medien gefunden – wird uebersprungen."
        fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "Keine passenden Upgrade-Pakete in den Medien gefunden."
    export DEBIAN_FRONTEND=noninteractive
    narrate "Upgrade von ${#files[@]} Paketen via apt-get install (dpkg upgradet gleichnamige Pakete automatisch) ..."
    run_with_progress "Upgrade von ${#files[@]} DEB-Paket(en) (kann 1-2 Minuten dauern) ..." \
        apt-get -y install "${files[@]}" || die "DEB-Upgrade fehlgeschlagen. Logfile pruefen: $LOGFILE"
    info "DEB-Pakete erfolgreich aktualisiert."
}

perform_upgrade() {
    echo
    narrate "==== Upgrade einer bestehenden IBM-MQ-Installation ===="
    [[ -n "$MEDIA" ]] || { usage; die "--media ist erforderlich (Modus: Upgrade)."; }
    [[ -e "$MEDIA" ]] || die "Medienpfad existiert nicht: $MEDIA"

    source_mqenv 2>/dev/null || true
    local old_version; old_version="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
    narrate "Aktuell installierte Version: ${old_version:-unbekannt}"

    # Medien vorbereiten und Version ERMITTELN, BEVOR irgendetwas gestoppt wird:
    # so laesst sich ein echtes (von IBM MQ nicht unterstuetztes) Downgrade
    # abfangen, ohne vorher schon Queue Manager/mqweb angehalten zu haben.
    prepare_media
    local media_version; media_version="$(get_media_mq_version)"
    narrate "Medien-Version: ${media_version:-unbekannt}"
    if [[ "$(would_be_real_downgrade "$old_version" "$media_version")" == "yes" ]]; then
        warn "ACHTUNG: Die installierten IBM-MQ-Pakete (Version $old_version) sind NEUER als diese"
        warn "Medien (Version $media_version). IBM MQ unterstuetzt KEIN Downgrade auf eine niedrigere"
        warn "Version/Release/Modification-Ebene - das Paket-Installationsskript von IBM selbst"
        warn "verweigert dies, unabhaengig von apt/rpm-Optionen. Ein Erzwingen ist NICHT moeglich."
        die "Abbruch: echtes Downgrade ($old_version -> $media_version) wird von IBM MQ nicht unterstuetzt. Bitte Installationsmedien mit Version >= $old_version fuer 'Upgrade' verwenden."
    fi

    local qms; qms="$(get_all_qm_names)"
    local qms_line="keine"
    if [[ -n "$qms" ]]; then
        qms_line="$(echo "$qms" | tr '\n' ' ')"
        narrate "Betroffene Queue Manager auf diesem Host (werden waehrend des Upgrades gestoppt): $qms_line"
    else
        narrate "Keine vorhandenen Queue Manager gefunden."
    fi

    narrate "ACHTUNG: Ein Upgrade der Version/Release/Modification (VRM) ist NICHT reversibel, sobald ein Queue Manager mit dem neuen Code gestartet wurde. Alle Queue Manager und die Web Console werden fuer die Dauer des Upgrades gestoppt (Downtime!)."
    local confirm_prompt
    confirm_prompt="Aktuelle Version: ${old_version:-unbekannt}  ->  Medien-Version: ${media_version:-unbekannt}
Betroffene Queue Manager: ${qms_line}

ACHTUNG: Ein VRM-Upgrade ist NICHT reversibel, sobald ein Queue Manager mit
dem neuen Code gestartet wurde. Alle Queue Manager und die Web Console
werden fuer die Dauer des Upgrades gestoppt (Downtime!).

Upgrade jetzt durchfuehren?"
    if [[ "$(ask_yes_no "$confirm_prompt" 'no')" != "yes" ]]; then
        cancel_to_menu "Abbruch durch Benutzer (Upgrade nicht bestaetigt)."
    fi

    if [[ "$(ask_yes_no 'Vor dem Upgrade /var/mqm sichern (dringend empfohlen)?' "$UPGRADE_BACKUP")" == "yes" ]]; then
        narrate "Sichere /var/mqm nach ${UPGRADE_BACKUP_DIR}.tar.gz ..."
        run_with_progress "Sichere /var/mqm ..." tar -czf "${UPGRADE_BACKUP_DIR}.tar.gz" -C / var/mqm \
            && info "Backup erstellt: ${UPGRADE_BACKUP_DIR}.tar.gz" \
            || warn "Backup fehlgeschlagen – bitte vor dem Fortfahren manuell sichern."
    fi

    # mqweb stoppen, falls aktiv
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ibmmq-web.service 2>/dev/null; then
        narrate "Stoppe mqweb-systemd-Service ..."
        systemctl stop ibmmq-web.service || true
    fi
    [[ -x "$MQ_INSTALL_PATH/bin/endmqweb" ]] && su -s /bin/bash mqm -c "'$MQ_INSTALL_PATH/bin/endmqweb'" >>"$LOGFILE" 2>&1 || true

    # Alle Queue Manager stoppen
    local qm
    for qm in $qms; do
        narrate "Stoppe Queue Manager '$qm' ..."
        su -s /bin/bash mqm -c "endmqm -w '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "'$qm' konnte nicht sauber gestoppt werden (evtl. bereits gestoppt)."
    done

    accept_license
    ui_menu_intro "Upgrade IBM MQ Pakete ($PKG_FORMAT)"
    case "$PKG_FORMAT" in
        rpm) upgrade_rpm_packages ;;
        deb) upgrade_deb_packages ;;
    esac
    post_install_setup
    info "Neue Version: ${MQ_INSTALLED_VERSION:-unbekannt} (vorher: ${old_version:-unbekannt})"

    # Queue Manager wieder starten (loest ggf. automatische Migration aus)
    for qm in $qms; do
        info "Starte Queue Manager '$qm' (Migration erfolgt automatisch, falls das VRM-Level gestiegen ist) ..."
        su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "'$qm' konnte nicht gestartet werden – bitte manuell pruefen (dspmq, AMQERR01.LOG)."
    done

    if [[ -x "$MQ_INSTALL_PATH/bin/strmqweb" ]]; then
        info "Starte mqweb-Service wieder (sofern konfiguriert) ..."
        "$MQ_INSTALL_PATH/bin/strmqweb" >>"$LOGFILE" 2>&1 \
            || warn "mqweb-Start uebersprungen/fehlgeschlagen (evtl. nicht konfiguriert)."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 UPGRADE ABGESCHLOSSEN
================================================================================
 Vorherige Version : ${old_version:-unbekannt}
 Neue Version      : ${MQ_INSTALLED_VERSION:-unbekannt}
 Queue Manager     : $(echo "$qms" | tr '\n' ' ')
 Backup            : $( [[ -f "${UPGRADE_BACKUP_DIR}.tar.gz" ]] && echo "${UPGRADE_BACKUP_DIR}.tar.gz" || echo "kein Backup erstellt" )
 Logfile           : $LOGFILE

 WICHTIG: Alle Queue Manager (dspmq, AMQERR01.LOG) und Anwendungen nach dem
 Upgrade pruefen. Ein Zurueckrollen auf die alte VRM-Version ist NICHT mehr
 moeglich, sobald ein Queue Manager mit dem neuen Code gestartet wurde.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5g) Zusatzfeature zu bestehender Installation hinzufuegen (z. B. MQTT/Telemetry, AMS)
#-------------------------------------------------------------------------------
perform_feature_install() {
    echo
    narrate "==== Zusatzfeature zu bestehender Installation hinzufuegen ===="
    [[ -n "$MEDIA" ]] || { usage; die "--media ist erforderlich (Modus: Feature-Installation)."; }
    [[ -e "$MEDIA" ]] || die "Medienpfad existiert nicht: $MEDIA"

    source_mqenv 2>/dev/null || true

    local have_mqtt="no" have_ams="no"
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        rpm -q MQSeriesXRService >/dev/null 2>&1 && have_mqtt="yes"
        rpm -q MQSeriesAMS       >/dev/null 2>&1 && have_ams="yes"
    else
        dpkg -s ibmmq-xrservice >/dev/null 2>&1 && have_mqtt="yes"
        dpkg -s ibmmq-ams       >/dev/null 2>&1 && have_ams="yes"
    fi
    narrate "Aktueller Stand: MQTT/Telemetry=$have_mqtt  AMS=$have_ams"

    local want_mqtt="$FEATURE_MQTT" want_ams="$FEATURE_AMS"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            local sel
            sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Zusatzfeature nachinstallieren" \
                --checklist "Bereits installiert: MQTT=$have_mqtt  AMS=$have_ams\nAuswaehlen, was installiert werden soll:" \
                "$rows" "$cols" 2 --separate-output \
                "MQTT" "MQTT/Telemetry (MQSeriesXRService) - MQTT-Clients anbinden" "$( [[ "$have_mqtt" == "yes" ]] && echo on || echo off )" \
                "AMS"  "Advanced Message Security (Nachrichtenverschluesselung/-signierung)" "$( [[ "$have_ams" == "yes" ]] && echo on || echo off )" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
            want_mqtt="no"; want_ams="no"
            local tag
            while IFS= read -r tag; do
                case "$tag" in
                    MQTT) want_mqtt="yes" ;;
                    AMS)  want_ams="yes" ;;
                esac
            done <<< "$sel"
        else
            want_mqtt="$(ask_yes_no 'MQTT/Telemetry (MQSeriesXRService) installieren?' "$( [[ "$have_mqtt" == "yes" ]] && echo yes || echo no )")"
            want_ams="$(ask_yes_no  'Advanced Message Security (AMS) installieren?'   "$( [[ "$have_ams"  == "yes" ]] && echo yes || echo no )")"
        fi
    fi

    if [[ "$want_mqtt" != "yes" && "$want_ams" != "yes" ]]; then
        info "Keine Auswahl getroffen – nichts zu tun."
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
        if [[ -n "$f" ]]; then files+=("$f"); else warn "MQTT/Telemetry-Paket nicht in den Medien gefunden."; fi
    fi
    if [[ "$want_ams" == "yes" && "$have_ams" != "yes" ]]; then
        if [[ "$PKG_FORMAT" == "rpm" ]]; then
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'MQSeriesAMS-*.rpm' | head -n1 || true)"
        else
            f="$(find "$MQ_SRC" -maxdepth 1 -name 'ibmmq-ams_*.deb' | head -n1 || true)"
        fi
        if [[ -n "$f" ]]; then files+=("$f"); else warn "AMS-Paket nicht in den Medien gefunden."; fi
    fi

    if [[ ${#files[@]} -gt 0 ]]; then
        narrate "Installiere ${#files[@]} zusaetzliche Paket(e) ..."
        if [[ "$PKG_FORMAT" == "rpm" ]]; then
            run_with_progress "Installiere ${#files[@]} zusaetzliche(s) Paket(e) ..." \
                rpm -ivh "${files[@]}" || die "Installation der Zusatzpakete fehlgeschlagen. Logfile pruefen: $LOGFILE"
        else
            export DEBIAN_FRONTEND=noninteractive
            run_with_progress "Installiere ${#files[@]} zusaetzliche(s) Paket(e) ..." \
                apt-get -y install "${files[@]}" || die "Installation der Zusatzpakete fehlgeschlagen. Logfile pruefen: $LOGFILE"
        fi
        info "Zusaetzliche Pakete installiert."
    else
        info "Keine neuen Pakete zu installieren (bereits vorhanden oder nicht ausgewaehlt)."
    fi

    # ---- MQTT/Telemetry auf einem Queue Manager aktivieren ----
    if [[ "$want_mqtt" == "yes" ]]; then
        local target_qm="$MQTT_QM"
        local all_qms; all_qms="$(get_all_qm_names)"
        if [[ -z "$target_qm" ]]; then
            if [[ -z "$all_qms" ]]; then
                warn "Keine Queue Manager gefunden – MQTT-Dienst kann nicht aktiviert werden. Bitte spaeter manuell einrichten."
            else
                narrate "Vorhandene Queue Manager: $(echo "$all_qms" | tr '\n' ' ')"
                target_qm="$(ask "Fuer welchen Queue Manager soll MQTT/Telemetry aktiviert werden? (vorhanden: $(echo "$all_qms" | tr '\n' ' '))" "$(echo "$all_qms" | head -n1)")"
            fi
        fi
        if [[ -n "$target_qm" ]]; then
            local mqxr_sample="$MQ_INSTALL_PATH/mqxr/samples/installMQXRService_unix.mqsc"
            if [[ -f "$mqxr_sample" ]]; then
                narrate "Richte SYSTEM.MQXR.SERVICE auf '$target_qm' ein (offizielles IBM-Sample-MQSC) ..."
                cat "$mqxr_sample" | su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                    || warn "Einrichten des MQXR-Service fehlgeschlagen – bitte Logfile pruefen."
                if [[ "$(ask_yes_no 'SYSTEM.MQTT.TRANSMIT.QUEUE anlegen und als Default-Transmit-Queue setzen?' "$MQTT_SET_DEFXMITQ")" == "yes" ]]; then
                    su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 <<EOSC || warn "Transmit-Queue-Konfiguration fehlgeschlagen."
DEFINE QLOCAL('SYSTEM.MQTT.TRANSMIT.QUEUE') USAGE(XMITQ) MAXDEPTH(100000) REPLACE
ALTER QMGR DEFXMITQ('SYSTEM.MQTT.TRANSMIT.QUEUE')
EOSC
                fi
                su -s /bin/bash mqm -c "echo 'START SERVICE(SYSTEM.MQXR.SERVICE)' | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                    || warn "Start von SYSTEM.MQXR.SERVICE fehlgeschlagen (laeuft evtl. schon oder QM nicht aktiv)."
                info "MQTT/Telemetry fuer '$target_qm' eingerichtet."
                info "Listener-Port/TLS pruefen mit: echo \"DISPLAY SERVICE(SYSTEM.MQXR.SERVICE) ALL\" | runmqsc $target_qm"
            else
                warn "Beispiel-MQSC fuer den Telemetry-Dienst nicht gefunden unter: $mqxr_sample"
                warn "Bitte MQTT/Telemetry gemaess IBM-Dokumentation manuell einrichten."
            fi
        fi
    fi

    if [[ "$want_ams" == "yes" ]]; then
        info "AMS-Paket verarbeitet. Hinweis: AMS-Schutzrichtlinien muessen separat je Queue"
        info "definiert werden (siehe IBM-Dokumentation zu 'AMS policies', setmqspl-Befehl)."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 ZUSATZFEATURE(S) VERARBEITET
================================================================================
 MQTT/Telemetry : $want_mqtt
 AMS            : $want_ams
 Logfile        : $LOGFILE
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5h) Backup eines oder aller Queue Manager erstellen
#-------------------------------------------------------------------------------
perform_backup() {
    echo
    narrate "==== Backup von Queue Manager(n) erstellen ===="

    source_mqenv 2>/dev/null || true

    local all_qms; all_qms="$(get_all_qm_names)"
    if [[ -z "$all_qms" ]]; then
        warn "Keine Queue Manager auf diesem Host gefunden – kein Backup moeglich."
        return 0
    fi

    # ---- Auswahl der zu sichernden Queue Manager ----
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
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Backup auswaehlen" \
            --checklist "Welche Queue Manager sollen gesichert werden?" "$rows" "$cols" "${#all_arr[@]}" \
            --separate-output "${items[@]}" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        while IFS= read -r qm; do
            [[ -n "$qm" ]] && selected_qms+=("$qm")
        done <<< "$sel"
    else
        info "Vorhandene Queue Manager:"
        local i=0
        for qm in "${all_arr[@]}"; do
            i=$((i+1))
            echo "  $i) $qm"
        done
        local choice
        read -r -p "Auswahl (Nummern kommagetrennt oder 'a' fuer alle) [a]: " choice < /dev/tty || true
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
        warn "Keine Queue Manager ausgewaehlt – Backup abgebrochen."
        return 0
    fi
    narrate "Ausgewaehlt fuer Backup: ${selected_qms[*]}"

    local stop_qm="$BACKUP_STOP_QM"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        stop_qm="$(ask_yes_no 'Queue Manager waehrend des Backups anhalten (konsistentes Daten-Backup, empfohlen)?' "$BACKUP_STOP_QM")"
    fi

    mkdir -p "$BACKUP_DIR" 2>/dev/null || die "Backup-Verzeichnis '$BACKUP_DIR' konnte nicht angelegt werden."
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    local qm cfg_file data_file was_running

    for qm in "${selected_qms[@]}"; do
        echo
        info "---- Backup fuer Queue Manager '$qm' ----"
        cfg_file="$BACKUP_DIR/${qm}-config-${ts}.mqsc"
        data_file="$BACKUP_DIR/${qm}-data-${ts}.tar.gz"

        # 1) Konfigurationsexport (dmpmqcfg) - laeuft auch bei aktivem QM ohne Downtime
        info "Exportiere Konfiguration (dmpmqcfg) nach $cfg_file ..."
        su -s /bin/bash mqm -c "dmpmqcfg -m '$qm' -x all -a" > "$cfg_file" 2>>"$LOGFILE" \
            || warn "Konfigurationsexport fuer '$qm' fehlgeschlagen (Queue Manager laeuft evtl. nicht)."

        # 2) Optional: QM anhalten fuer ein konsistentes Daten-/Log-Backup
        was_running="no"
        if [[ "$stop_qm" == "yes" ]]; then
            if su -s /bin/bash mqm -c "dspmq -m '$qm'" 2>/dev/null | grep -q "STATUS(Running)"; then
                was_running="yes"
                info "Stoppe '$qm' fuer ein konsistentes Daten-Backup ..."
                su -s /bin/bash mqm -c "endmqm -w '$qm'" >>"$LOGFILE" 2>&1 \
                    || warn "'$qm' konnte nicht sauber gestoppt werden – Backup erfolgt trotzdem."
            fi
        else
            warn "'$qm' bleibt waehrend des Daten-Backups aktiv – das Archiv kann inkonsistent sein."
        fi

        # 3) Daten-/Log-Verzeichnisse sichern
        info "Sichere Daten-/Log-Verzeichnisse nach $data_file ..."
        tar -czf "$data_file" -C / "var/mqm/qmgrs/${qm}" "var/mqm/log/${qm}" >>"$LOGFILE" 2>&1 \
            || warn "Sichern der Daten-/Log-Verzeichnisse fuer '$qm' fehlgeschlagen."

        # 4) QM ggf. wieder starten
        if [[ "$was_running" == "yes" ]]; then
            info "Starte '$qm' wieder ..."
            su -s /bin/bash mqm -c "strmqm '$qm'" >>"$LOGFILE" 2>&1 \
                || warn "'$qm' konnte nicht wieder gestartet werden – bitte manuell pruefen."
        fi

        info "Backup fuer '$qm' abgeschlossen: $cfg_file / $data_file"
    done

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 BACKUP ABGESCHLOSSEN
================================================================================
 Queue Manager      : ${selected_qms[*]}
 Backup-Verzeichnis : $BACKUP_DIR
 Zeitstempel        : $ts
 Logfile            : $LOGFILE

 Hinweis:
   - Die Konfiguration (*-config-*.mqsc) laesst sich jederzeit per
     'runmqsc <QM> < datei.mqsc' auf einen (neuen) Queue Manager zurueckspielen.
   - Das Daten-/Log-Archiv (*-data-*.tar.gz) enthaelt die Warteschlangeninhalte
     und muss bei einer Wiederherstellung in /var/mqm/qmgrs bzw. /var/mqm/log
     entpackt werden, waehrend der Ziel-Queue-Manager gestoppt ist.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5i) Queue Manager aus einem Backup wiederherstellen (Restore)
#-------------------------------------------------------------------------------
perform_restore() {
    echo
    narrate "==== Wiederherstellung eines Queue Managers aus einem Backup ===="

    # ---- Quellverzeichnis mit den Backup-Dateien waehlen ----
    local src_dir="${RESTORE_SRC_DIR:-$BACKUP_DIR}"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        src_dir="$(ask 'Quellverzeichnis mit den Backup-Dateien (*-config-*.mqsc / *-data-*.tar.gz)' "$src_dir")"
    fi
    [[ -d "$src_dir" ]] || die "Verzeichnis '$src_dir' existiert nicht."

    local -a cfg_files=()
    while IFS= read -r f; do [[ -n "$f" ]] && cfg_files+=("$f"); done \
        < <(find "$src_dir" -maxdepth 1 -name '*-config-*.mqsc' 2>/dev/null | sort)
    [[ ${#cfg_files[@]} -gt 0 ]] || die "Keine Backup-Dateien (*-config-*.mqsc) in '$src_dir' gefunden."

    # ---- Welches Backup soll wiederhergestellt werden? ----
    local chosen_cfg=""
    if [[ -n "$RESTORE_QM" ]]; then
        if [[ -n "$RESTORE_TS" ]]; then
            chosen_cfg="$src_dir/${RESTORE_QM}-config-${RESTORE_TS}.mqsc"
            [[ -f "$chosen_cfg" ]] || die "Backup-Datei nicht gefunden: $chosen_cfg"
        else
            # Neuestes Backup fuer diesen QM-Namen waehlen
            chosen_cfg="$(find "$src_dir" -maxdepth 1 -name "${RESTORE_QM}-config-*.mqsc" 2>/dev/null | sort | tail -n1)"
            [[ -n "$chosen_cfg" ]] || die "Kein Backup fuer QM '$RESTORE_QM' in '$src_dir' gefunden."
        fi
    elif [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Ohne Angabe: neuestes vorhandenes Backup insgesamt verwenden
        chosen_cfg="${cfg_files[-1]}"
    elif [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() i=1 f
        for f in "${cfg_files[@]}"; do
            items+=("$i" "$(basename "$f")")
            i=$((i+1))
        done
        local idx
        idx="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Backup auswaehlen" \
            --menu "Welches Backup soll wiederhergestellt werden?" "$rows" "$cols" "${#cfg_files[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        chosen_cfg="${cfg_files[$((idx-1))]}"
    else
        info "Verfuegbare Backups in '$src_dir':"
        local i=1 f
        for f in "${cfg_files[@]}"; do
            echo "  $i) $(basename "$f")"
            i=$((i+1))
        done
        local choice
        read -r -p "Auswahl [${#cfg_files[@]}]: " choice < /dev/tty || true
        choice="${choice:-${#cfg_files[@]}}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#cfg_files[@]}" ]] || choice="${#cfg_files[@]}"
        chosen_cfg="${cfg_files[$((choice-1))]}"
    fi

    # ---- QM-Name und Zeitstempel aus Dateinamen ableiten: <QM>-config-<TS>.mqsc ----
    local base; base="$(basename "$chosen_cfg" .mqsc)"
    local qm="${base%-config-*}"
    local ts="${base##*-config-}"
    local data_file="$src_dir/${qm}-data-${ts}.tar.gz"
    narrate "Gewaehltes Backup: Queue Manager='$qm'  Zeitstempel='$ts'"
    narrate "Konfigurationsdatei: $chosen_cfg"
    local restore_hint=""
    if [[ -f "$data_file" ]]; then
        narrate "Zugehoeriges Datenarchiv gefunden: $data_file"
    else
        warn "Kein zugehoeriges Datenarchiv gefunden (erwartet: $data_file) – nur Konfigurations-Restore moeglich."
        restore_hint=$'\n\nHinweis: Kein Datenarchiv gefunden - "full" ist fuer dieses Backup nicht verfuegbar.'
    fi

    # ---- Restore-Art waehlen ----
    local restore_mode="$RESTORE_MODE"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        if [[ "$UI_MODE" == "tui" ]]; then
            read -r rows cols <<< "$(ui_dims)"
            restore_mode="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Restore-Art" \
                --menu "Queue Manager '$qm' (Zeitstempel $ts) wiederherstellen:${restore_hint}" "$rows" "$cols" 2 \
                "config" "Nur Konfiguration (MQSC-Reimport, sicher, live moeglich)" \
                "full"   "Vollstaendig (Daten-/Log-Archiv einspielen, ueberschreibt Daten)" \
                3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        else
            echo "  1) config - Nur Konfiguration (MQSC-Reimport, sicher, live moeglich)"
            echo "  2) full   - Vollstaendig (Daten-/Log-Archiv einspielen, ueberschreibt Daten)"
            local rchoice
            read -r -p "Restore-Art [1]: " rchoice < /dev/tty || true
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
        [[ -f "$data_file" ]] || die "Kein Datenarchiv fuer vollstaendige Wiederherstellung gefunden: $data_file"
        narrate "ACHTUNG: Vollstaendige Wiederherstellung UEBERSCHREIBT alle aktuellen Daten von '$qm' unwiderruflich!"
        if [[ "$(ask_yes_no "ACHTUNG: Ueberschreibt alle aktuellen Daten von '$qm' unwiderruflich!\n\nWirklich '$qm' komplett aus dem Backup vom $ts wiederherstellen?" 'no')" != "yes" ]]; then
            cancel_to_menu "Abbruch durch Benutzer (Restore nicht bestaetigt)."
        fi

        if [[ "$qm_exists" == "yes" ]]; then
            info "Stoppe '$qm' ..."
            su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 \
                || warn "'$qm' konnte nicht sauber gestoppt werden (evtl. bereits gestoppt)."
            info "Entferne aktuelle Daten-/Log-Verzeichnisse von '$qm' ..."
            rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
                || warn "Loeschen der alten Verzeichnisse teilweise fehlgeschlagen."
        else
            info "Queue Manager '$qm' existiert noch nicht – lege ihn zunaechst leer an (fuer mqs.ini-Registrierung) ..."
            su -s /bin/bash mqm -c "crtmqm '$qm'" >>"$LOGFILE" 2>&1 || die "crtmqm fuer '$qm' fehlgeschlagen."
            su -s /bin/bash mqm -c "endmqm -i '$qm'" >>"$LOGFILE" 2>&1 || true
            rm -rf "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" || true
        fi

        info "Entpacke Datenarchiv nach /var/mqm ..."
        tar -xzf "$data_file" -C / >>"$LOGFILE" 2>&1 || die "Entpacken des Datenarchivs fehlgeschlagen."
        chown -R mqm:mqm "/var/mqm/qmgrs/${qm}" "/var/mqm/log/${qm}" 2>>"$LOGFILE" \
            || warn "chown auf 'mqm' fehlgeschlagen – Berechtigungen bitte pruefen."

        info "Starte '$qm' ..."
        start_qmgr_robust "$qm"
        info "Vollstaendige Wiederherstellung von '$qm' abgeschlossen."
    else
        if [[ "$qm_exists" != "yes" ]]; then
            info "Queue Manager '$qm' existiert nicht – lege ihn frisch an ..."
            su -s /bin/bash mqm -c "crtmqm '$qm'" >>"$LOGFILE" 2>&1 || die "crtmqm fuer '$qm' fehlgeschlagen."
            start_qmgr_robust "$qm"
        fi
        info "Spiele Konfiguration aus '$chosen_cfg' ein (runmqsc) ..."
        cat "$chosen_cfg" | su -s /bin/bash mqm -c "runmqsc '$qm'" >>"$LOGFILE" 2>&1 \
            || warn "Einspielen der Konfiguration meldete Fehler/Warnungen – Logfile pruefen."
        info "Konfigurations-Restore fuer '$qm' abgeschlossen."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 WIEDERHERSTELLUNG ABGESCHLOSSEN
================================================================================
 Queue Manager   : $qm
 Restore-Art     : $restore_mode
 Quelle          : $chosen_cfg$( [[ "$restore_mode" == "full" ]] && echo ", $data_file" )
 Logfile         : $LOGFILE

 Bitte den Queue Manager pruefen: dspmq, AMQERR01.LOG, Anwendungen testen.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5j) IBM-MQ-Installation vollstaendig entfernen (Deinstallation)
#-------------------------------------------------------------------------------
perform_uninstall() {
    echo
    narrate "==== IBM-MQ-Installation vollstaendig entfernen ===="

    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    local qms_line="keine"
    [[ -n "$qms" ]] && qms_line="$(echo "$qms" | tr '\n' ' ')"

    local pkg_list=""
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        pkg_list="$(rpm -qa --qf '%{NAME}\n' 2>/dev/null | grep '^MQSeries' || true)"
    else
        pkg_list="$(dpkg-query -W -f='${Package}\n' 2>/dev/null | grep '^ibmmq-' || true)"
    fi

    narrate "ACHTUNG: Diese Aktion entfernt UNWIDERRUFLICH:"
    narrate "  - Alle Queue Manager auf diesem Host samt Nachrichten/Daten: $qms_line"
    narrate "  - Alle IBM-MQ-Pakete ($([[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l) Pakete" || echo "keine gefunden"))"
    narrate "  - Zugehoerige systemd-Dienste und Bequemlichkeits-Aliase"
    narrate "Diese Aktion kann NICHT rueckgaengig gemacht werden."

    local confirm_prompt
    confirm_prompt="Betroffene Queue Manager: ${qms_line}
Gefundene Pakete: $( [[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l)" || echo "0" )

ACHTUNG: Diese Aktion loescht ALLE Queue Manager samt Daten und entfernt
alle IBM-MQ-Pakete UNWIDERRUFLICH von diesem Host.

Wirklich vollstaendig entfernen?"
    local proceed="$UNINSTALL_CONFIRM"
    if [[ -z "$proceed" ]]; then
        proceed="$(ask_yes_no "$confirm_prompt" 'no')"
    fi
    if [[ "$proceed" != "yes" ]]; then
        cancel_to_menu "Abbruch durch Benutzer (Deinstallation nicht bestaetigt)."
    fi

    if [[ "$(ask_yes_no 'Vor der Entfernung noch ein Backup aller Queue Manager erstellen (empfohlen)?' "$UNINSTALL_BACKUP_FIRST")" == "yes" ]]; then
        info "Erstelle Backup vor der Deinstallation ..."
        BACKUP_QMS="all"; BACKUP_STOP_QM="yes"
        perform_backup || warn "Backup meldete Probleme - Deinstallation wird trotzdem fortgesetzt."
    fi

    local remove_user="$UNINSTALL_REMOVE_USER"
    if [[ "$NON_INTERACTIVE" != "yes" ]]; then
        remove_user="$(ask_yes_no 'Zusaetzlich den Benutzer/die Gruppe "mqm" sowie /var/mqm vollstaendig entfernen (nur sinnvoll, wenn IBM MQ nie wieder auf diesem Host installiert werden soll)?' "$UNINSTALL_REMOVE_USER")"
    fi

    # ---- mqweb stoppen ----
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ibmmq-web.service 2>/dev/null; then
        info "Stoppe mqweb-systemd-Service ..."
        systemctl disable --now ibmmq-web.service >>"$LOGFILE" 2>&1 || true
    fi
    [[ -x "$MQ_INSTALL_PATH/bin/endmqweb" ]] && su -s /bin/bash mqm -c "'$MQ_INSTALL_PATH/bin/endmqweb'" >>"$LOGFILE" 2>&1 || true

    # ---- Alle Queue Manager sauber loeschen ----
    local qm failed_qms=()
    for qm in $qms; do
        info "Entferne Queue Manager '$qm' ..."
        if command -v systemctl >/dev/null 2>&1; then
            systemctl disable --now "ibmmq-${qm}.service" >>"$LOGFILE" 2>&1 || true
        fi
        delete_qmgr_robust "$qm" || failed_qms+=("$qm")
    done

    # ---- systemd-Unit-Dateien aufraeumen ----
    if [[ -d /etc/systemd/system ]]; then
        rm -f /etc/systemd/system/ibmmq-*.service 2>>"$LOGFILE" || true
        command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
    fi

    # ---- Bequemlichkeits-Aliase entfernen ----
    if [[ -f /etc/profile.d/mqm-aliases.sh ]]; then
        info "Entferne Alias-Datei /etc/profile.d/mqm-aliases.sh ..."
        rm -f /etc/profile.d/mqm-aliases.sh 2>>"$LOGFILE" || warn "Alias-Datei konnte nicht entfernt werden."
    fi

    # ---- /etc/profile.d/mqenv.sh entfernen ----
    rm -f /etc/profile.d/mqenv.sh 2>>"$LOGFILE" || true

    # ---- Pakete entfernen ----
    info "Entferne IBM-MQ-Pakete ..."
    if [[ "$PKG_FORMAT" == "rpm" ]]; then
        if [[ -n "$pkg_list" ]]; then
            run_with_progress "Entferne $(echo "$pkg_list" | wc -l) RPM-Paket(e) ..." \
                rpm -e $(echo "$pkg_list") \
                || warn "Einige RPM-Pakete konnten nicht entfernt werden - Logfile pruefen."
        fi
    else
        export DEBIAN_FRONTEND=noninteractive
        if [[ -n "$pkg_list" ]]; then
            run_with_progress "Entferne $(echo "$pkg_list" | wc -l) DEB-Paket(e) ..." \
                apt-get -y purge $(echo "$pkg_list") \
                || warn "Einige DEB-Pakete konnten nicht entfernt werden - Logfile pruefen."
            apt-get -y autoremove >>"$LOGFILE" 2>&1 || true
        fi
    fi

    # ---- Optional: mqm-User/-Gruppe und /var/mqm vollstaendig entfernen ----
    if [[ "$remove_user" == "yes" ]]; then
        warn "Entferne Benutzer 'mqm', Gruppe 'mqm' und /var/mqm vollstaendig ..."
        if [[ ${#failed_qms[@]} -gt 0 ]]; then
            warn "Hinweis: Fuer folgende QM(s) schlug die saubere Loeschung fehl, ihre Daten werden nun"
            warn "trotzdem mit /var/mqm entfernt: ${failed_qms[*]}"
        fi
        id mqm >/dev/null 2>&1 && userdel -r mqm >>"$LOGFILE" 2>&1
        getent group mqm >/dev/null 2>&1 && groupdel mqm >>"$LOGFILE" 2>&1 || true
        rm -rf /var/mqm 2>>"$LOGFILE" || warn "/var/mqm konnte nicht vollstaendig entfernt werden."
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 DEINSTALLATION ABGESCHLOSSEN
================================================================================
 Entfernte Queue Manager : ${qms_line}
$( [[ ${#failed_qms[@]} -gt 0 ]] && echo " Nicht sauber entfernt (nur Verzeichnisse geloescht): ${failed_qms[*]}" )
 Entfernte Pakete        : $( [[ -n "$pkg_list" ]] && echo "$(echo "$pkg_list" | wc -l)" || echo "0" )
 mqm-User/-Gruppe/var/mqm: $( [[ "$remove_user" == "yes" ]] && echo "entfernt" || echo "beibehalten" )
 Logfile                 : $LOGFILE

 Hinweis: '$MQ_INSTALL_PATH' (Installationsverzeichnis) wird von den Paketmanagern
 in der Regel automatisch mit entfernt. Falls Reste verbleiben, manuell pruefen.
================================================================================
EOF
}

#-------------------------------------------------------------------------------
# 5k) Objekte fuer einen bestehenden Queue Manager erstellen (Kanaele, Listener)
#-------------------------------------------------------------------------------
perform_create_objects() {
    echo
    narrate "==== Objekte fuer Queue Manager erstellen ===="
    if ! id mqm >/dev/null 2>&1; then
        die "Benutzer 'mqm' existiert nicht - IBM MQ scheint auf diesem Host nicht installiert zu sein."
    fi
    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    [[ -n "$qms" ]] || die "Keine Queue Manager auf diesem Host gefunden."
    local -a all_arr=()
    while IFS= read -r q; do [[ -n "$q" ]] && all_arr+=("$q"); done <<< "$qms"

    # ---- Queue Manager auswaehlen ----
    local target_qm=""
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() qm
        for qm in "${all_arr[@]}"; do items+=("$qm" ""); done
        target_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Queue Manager waehlen" \
            --menu "Fuer welchen Queue Manager sollen Objekte erstellt werden?" "$rows" "$cols" "${#all_arr[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
    else
        info "Vorhandene Queue Manager:"
        local i=0
        for qm in "${all_arr[@]}"; do i=$((i+1)); echo "  $i) $qm"; done
        local choice
        read -r -p "Auswahl [1]: " choice < /dev/tty || true
        choice="${choice:-1}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#all_arr[@]}" ]] || choice=1
        target_qm="${all_arr[$((choice-1))]}"
    fi
    [[ -n "$target_qm" ]] || cancel_to_menu "Kein Queue Manager ausgewaehlt."

    # ---- Welche Objekte sollen erstellt werden? ----
    local -a to_create=()
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Objekte fuer $target_qm" \
            --checklist "Was soll erstellt werden?" "$rows" "$cols" 2 --separate-output \
            "CHANNEL"  "Verbindungskanal fuer MQ Explorer/Client (SVRCONN)" on \
            "LISTENER" "Zusaetzlicher TCP-Listener (neuer Port)" off \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
        local tag
        while IFS= read -r tag; do to_create+=("$tag"); done <<< "$sel"
    else
        local want_c want_l
        want_c="$(ask_yes_no 'Verbindungskanal (SVRCONN) fuer MQ Explorer/Client anlegen?' 'yes')"
        want_l="$(ask_yes_no 'Zusaetzlichen TCP-Listener anlegen?' 'no')"
        [[ "$want_c" == "yes" ]] && to_create+=("CHANNEL")
        [[ "$want_l" == "yes" ]] && to_create+=("LISTENER")
    fi
    if [[ ${#to_create[@]} -eq 0 ]]; then
        info "Keine Auswahl getroffen - nichts zu tun."
        return 0
    fi

    # ---- Details abfragen und MQSC vorbereiten ----
    local mqsc_file; mqsc_file="$(mktemp /tmp/objects.XXXXXX.mqsc)"
    : > "$mqsc_file"
    local summary="" cname="" cuser="" lname="" lport=""

    local item
    for item in "${to_create[@]}"; do
        case "$item" in
            CHANNEL)
                cname="$(ask 'Name des neuen Kanals (SVRCONN)' 'EXPLORER.SVRCONN')"
                cuser="$(ask 'MCAUSER (nicht-privilegierter Anwendungs-Benutzer)' "${MQ_APP_USER:-mqapp}")"
                local ctls; ctls="$(ask_yes_no 'TLS fuer diesen Kanal erfordern?' 'no')"
                {
                    echo "* Dedizierter Kanal mit festem, nicht-privilegiertem MCAUSER (IBM Best Practice:"
                    echo "* nie SYSTEM.DEF.SVRCONN fuer Anwendungen/MQ-Explorer verwenden)"
                    if [[ "$ctls" == "yes" ]]; then
                        echo "DEFINE CHANNEL('$cname') CHLTYPE(SVRCONN) MCAUSER('$cuser') +"
                        echo "       SSLCIPH('${TLS_CIPHER:-ANY_TLS12_OR_HIGHER}') SSLCAUTH(OPTIONAL) REPLACE"
                    else
                        echo "DEFINE CHANNEL('$cname') CHLTYPE(SVRCONN) MCAUSER('$cuser') REPLACE"
                    fi
                    echo "SET CHLAUTH('$cname') TYPE(ADDRESSMAP) ADDRESS('*') +"
                    echo "    USERSRC(CHANNEL) CHCKCLNT(REQUIRED) +"
                    echo "    DESCR('Zusaetzlicher Anwendungszugriff') ACTION(REPLACE)"
                } >> "$mqsc_file"
                summary+="  Kanal '$cname' (MCAUSER: $cuser, TLS: $ctls)"$'\n'
                ;;
            LISTENER)
                lname="$(ask 'Name des neuen Listeners' 'LISTENER.TCP2')"
                lport="$(ask 'Port des neuen Listeners' '1415')"
                {
                    echo "* Zusaetzlicher, dedizierter TCP-Listener"
                    echo "DEFINE LISTENER('$lname') TRPTYPE(TCP) PORT($lport) CONTROL(QMGR) REPLACE"
                    echo "START LISTENER('$lname')"
                } >> "$mqsc_file"
                summary+="  Listener '$lname' auf Port $lport"$'\n'
                ;;
        esac
    done

    info "Wende MQSC auf '$target_qm' an ..."
    cat "$mqsc_file" | su -s /bin/bash mqm -c "runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
        || die "Anwenden der MQSC auf '$target_qm' fehlgeschlagen. Logfile pruefen: $LOGFILE"
    rm -f "$mqsc_file"

    # Least Privilege ueber die gemeinsame Berechtigungsgruppe (nicht einzeln
    # je Benutzer): MCAUSER des neuen Kanals der Gruppe hinzufuegen und die
    # Gruppe (idempotent, unschaedlich bei erneutem Aufruf) mit QMGR-connect/
    # inq fuer diesen QM ausstatten.
    if [[ -n "$cuser" ]]; then
        getent group "$MQ_APP_GROUP" >/dev/null || groupadd "$MQ_APP_GROUP"
        if id "$cuser" >/dev/null 2>&1; then
            if ! id -nG "$cuser" | grep -qw "$MQ_APP_GROUP"; then
                usermod -aG "$MQ_APP_GROUP" "$cuser"
                info "'$cuser' zur Berechtigungsgruppe '$MQ_APP_GROUP' hinzugefuegt."
            fi
        else
            warn "OS-Benutzer '$cuser' existiert nicht - Gruppenzuordnung uebersprungen (nur MCAUSER in MQSC gesetzt)."
        fi
        su -s /bin/bash mqm -c "setmqaut -m '$target_qm' -t qmgr -g '$MQ_APP_GROUP' +connect +inq" >>"$LOGFILE" 2>&1 \
            || warn "setmqaut (Gruppe '$MQ_APP_GROUP') fuer '$target_qm' fehlgeschlagen - bitte manuell pruefen."
    fi

    # Firewall-Port fuer einen neuen Listener oeffnen (optional)
    if [[ -n "$lport" ]]; then
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
            if [[ "$(ask_yes_no "Port $lport/tcp in firewalld oeffnen?" 'yes')" == "yes" ]]; then
                firewall-cmd --permanent --add-port="${lport}/tcp" >>"$LOGFILE" 2>&1 || true
                firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            fi
        elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
            if [[ "$(ask_yes_no "Port $lport/tcp in ufw oeffnen?" 'yes')" == "yes" ]]; then
                ufw allow "${lport}/tcp" >>"$LOGFILE" 2>&1 || true
            fi
        fi
    fi

    cat <<EOF | tee -a "$LOGFILE"

================================================================================
 OBJEKTE FUER '$target_qm' ERSTELLT
================================================================================
$summary
EOF

    if [[ -n "$cname" ]]; then
        local host_fqdn; host_fqdn="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo '<host>')"
        local host_ips; host_ips="$(hostname -I 2>/dev/null | tr -s ' ' | sed 's/ *$//')"
        cat <<EOF | tee -a "$LOGFILE"
 MQ-EXPLORER-VERBINDUNGSPARAMETER:
   Queue manager name .......... : $target_qm
   Host name or IP address ..... : $host_fqdn   (oder: ${host_ips:-<ip-adresse>})
   Server-connection channel ... : $cname
   User ID ...................... : $cuser  (+ dessen OS-Passwort, falls CONNAUTH aktiv)
   Berechtigungsgruppe .......... : $MQ_APP_GROUP (setmqaut-Rechte liegen auf dieser Gruppe)
================================================================================
EOF
    fi
}

#-------------------------------------------------------------------------------
# 5l) SSL/TLS-Verwaltung (Self-Signed und "echte" CA-Zertifikate)
#-------------------------------------------------------------------------------
# Fragt, ob fuer ein neues Key-Repository ein eigenes Passwort vergeben oder
# eines automatisch generiert werden soll. Gibt das gewaehlte Passwort aus.
# ask_secret() erledigt bereits Bestaetigung/Leer-Pruefung/Wiederholung selbst.
choose_keydb_password() {
    local use_own
    use_own="$(ask_yes_no 'Eigenes Passwort fuer das Key-Repository vergeben (statt automatisch generiert)?' 'no')"
    if [[ "$use_own" == "yes" ]]; then
        ask_secret 'Passwort fuer das Key-Repository' ''
    else
        openssl rand -base64 18 2>/dev/null || echo "Chg-Me-$(date +%s)"
    fi
}

# Workflow fuer ein "echtes" CA-Zertifikat (IBM Best Practice, in dieser
# Reihenfolge): 1) CSR erstellen -> 2) an die CA senden -> 3) Root-/Zwischen-
# zertifikate der CA als "Trust" hinzufuegen (WICHTIG: VOR Schritt 4, sonst
# schlaegt die Trust-Chain-Pruefung fehl) -> 4) das von der CA signierte
# Zertifikat "empfangen" (runmqakm -cert -receive - NICHT -cert -add, das
# wuerde es nicht mit dem privaten Schluessel verknuepfen und unbrauchbar
# machen). Alle Aktionen nutzen "-stashed" (kein Passwort noetig), da das
# Key-Repository bei der Erstellung immer mit "-stash" angelegt wird (auch
# bei einem selbst vergebenen Passwort - das Stash-File erlaubt spaeteren
# Kommandos den Zugriff, ohne das Passwort jedes Mal erneut einzugeben;
# das Passwort bleibt trotzdem gueltig und kann z. B. in iKeyman genutzt werden).
perform_tls_management() {
    echo
    narrate "==== SSL/TLS-Verwaltung ===="
    if ! id mqm >/dev/null 2>&1; then
        die "Benutzer 'mqm' existiert nicht - IBM MQ scheint auf diesem Host nicht installiert zu sein."
    fi
    source_mqenv 2>/dev/null || true

    local qms; qms="$(get_all_qm_names)"
    [[ -n "$qms" ]] || die "Keine Queue Manager auf diesem Host gefunden."
    local -a all_arr=()
    while IFS= read -r q; do [[ -n "$q" ]] && all_arr+=("$q"); done <<< "$qms"

    # ---- Queue Manager auswaehlen ----
    local target_qm=""
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local items=() qm
        for qm in "${all_arr[@]}"; do items+=("$qm" ""); done
        target_qm="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Queue Manager waehlen" \
            --menu "Fuer welchen Queue Manager soll SSL/TLS verwaltet werden?" "$rows" "$cols" "${#all_arr[@]}" \
            "${items[@]}" 3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
    else
        info "Vorhandene Queue Manager:"
        local i=0
        for qm in "${all_arr[@]}"; do i=$((i+1)); echo "  $i) $qm"; done
        local choice
        read -r -p "Auswahl [1]: " choice < /dev/tty || true
        choice="${choice:-1}"
        [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 && "$choice" -le "${#all_arr[@]}" ]] || choice=1
        target_qm="${all_arr[$((choice-1))]}"
    fi
    [[ -n "$target_qm" ]] || cancel_to_menu "Kein Queue Manager ausgewaehlt."

    local ssldir="/var/mqm/qmgrs/${target_qm}/ssl"
    local keydb="${ssldir}/key"
    local kdb_file="${keydb}.kdb"
    su -s /bin/bash mqm -c "mkdir -p '$ssldir'" >>"$LOGFILE" 2>&1 || true
    local kdb_exists="no"; [[ -f "$kdb_file" ]] && kdb_exists="yes"

    # ---- Aktion auswaehlen ----
    local action="SELFSIGNED"
    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        action="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "SSL/TLS fuer $target_qm (Repository: $( [[ "$kdb_exists" == "yes" ]] && echo vorhanden || echo "noch nicht angelegt" ))" \
            --menu "Was moechten Sie tun?" "$rows" "$cols" 7 \
            "SELFSIGNED" "Self-Signed-Zertifikat erstellen/erneuern (Schnelleinstieg, Test)" \
            "CSR"        "CSR fuer eine echte CA erstellen (Best Practice, Produktion)" \
            "TRUST"      "CA-Root-/Zwischenzertifikat als vertrauenswuerdig hinzufuegen" \
            "RECEIVE"    "Signiertes Zertifikat von der CA einspielen" \
            "LIST"       "Zertifikate im Repository anzeigen" \
            "DETAILS"    "Details/Ablaufdatum eines Zertifikats anzeigen" \
            "PASSWORD"   "Passwort des Key-Repository aendern" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch durch Benutzer."
    else
        echo "Key-Repository fuer '$target_qm': $( [[ "$kdb_exists" == "yes" ]] && echo "vorhanden ($kdb_file)" || echo "noch nicht angelegt" )"
        echo "  1) Self-Signed-Zertifikat erstellen/erneuern (Schnelleinstieg, Test)"
        echo "  2) CSR fuer eine echte CA erstellen (Best Practice, Produktion)"
        echo "  3) CA-Root-/Zwischenzertifikat als vertrauenswuerdig hinzufuegen"
        echo "  4) Signiertes Zertifikat von der CA einspielen"
        echo "  5) Zertifikate im Repository anzeigen"
        echo "  6) Details/Ablaufdatum eines Zertifikats anzeigen"
        echo "  7) Passwort des Key-Repository aendern"
        local achoice
        read -r -p "Auswahl [1]: " achoice < /dev/tty || true
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
            local tls_label; tls_label="$(ask 'Zertifikats-Label' "qm.${target_qm,,}")"
            local dn_default="${TLS_CERT_DN#*,}"
            [[ "$dn_default" == "$TLS_CERT_DN" ]] && dn_default="O=Example,C=DE"
            local cert_dn; cert_dn="$(ask 'Distinguished Name (DN)' "CN=${target_qm},${dn_default}")"
            if [[ "$kdb_exists" != "yes" ]]; then
                local tlspw; tlspw="$(choose_keydb_password)"
                su -s /bin/bash mqm -c "runmqakm -keydb -create -db '$kdb_file' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
                    || die "Key-Repository-Erstellung fuer '$target_qm' fehlgeschlagen."
                info "Key-Repository fuer '$target_qm' angelegt: $kdb_file"
            fi
            su -s /bin/bash mqm -c "runmqakm -cert -create -db '$kdb_file' -stashed -label '$tls_label' -dn '$cert_dn' -size 2048 -sig_alg SHA256WithRSA -expire 365" >>"$LOGFILE" 2>&1 \
                || die "Zertifikat-Erstellung fuer '$target_qm' fehlgeschlagen."
            su -s /bin/bash mqm -c "echo \"ALTER QMGR SSLKEYR('$keydb') CERTLABL('$tls_label')
REFRESH SECURITY TYPE(SSL)\" | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                || warn "ALTER QMGR/REFRESH SECURITY meldete Probleme - bitte manuell pruefen."
            info "Self-Signed-Zertifikat '$tls_label' fuer '$target_qm' erstellt und aktiviert (SSLKEYR/CERTLABL gesetzt, Security-Cache aktualisiert)."
            warn "Hinweis: Self-Signed-Zertifikate sind fuer Tests geeignet. Fuer Produktion empfiehlt"
            warn "IBM ein von einer echten CA signiertes Zertifikat (siehe Menuepunkt 'CSR erstellen')."
            ;;
        CSR)
            if [[ "$kdb_exists" != "yes" ]]; then
                local tlspw; tlspw="$(choose_keydb_password)"
                su -s /bin/bash mqm -c "runmqakm -keydb -create -db '$kdb_file' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
                    || die "Key-Repository-Erstellung fuer '$target_qm' fehlgeschlagen."
                info "Key-Repository fuer '$target_qm' angelegt: $kdb_file"
            fi
            local tls_label; tls_label="$(ask 'Zertifikats-Label (wird spaeter als CERTLABL gesetzt)' "qm.${target_qm,,}")"
            local dn_default="${TLS_CERT_DN#*,}"
            [[ "$dn_default" == "$TLS_CERT_DN" ]] && dn_default="O=Example,C=DE"
            local cert_dn; cert_dn="$(ask 'Distinguished Name (DN) fuer die CSR' "CN=${target_qm},${dn_default}")"
            local csr_file="${ssldir}/${target_qm}.csr"
            su -s /bin/bash mqm -c "runmqakm -certreq -create -db '$kdb_file' -stashed -label '$tls_label' -dn '$cert_dn' -size 2048 -sigalg SHA256WithRSA -file '$csr_file'" >>"$LOGFILE" 2>&1 \
                || die "CSR-Erstellung fuer '$target_qm' fehlgeschlagen."
            chown mqm:mqm "$csr_file" 2>/dev/null || true
            cat <<EOF | tee -a "$LOGFILE"

================================================================================
 CSR ERSTELLT FUER '$target_qm'
================================================================================
 Datei  : $csr_file
 Label  : $tls_label
 DN     : $cert_dn

 Naechste Schritte:
   1. Diese Datei an Ihre Zertifizierungsstelle (CA) senden.
   2. Nach Erhalt: Root-/Zwischenzertifikate der CA ueber den Menuepunkt
      'CA-Root-/Zwischenzertifikat hinzufuegen' als vertrauenswuerdig einspielen
      (WICHTIG: dieser Schritt muss VOR Schritt 3 erfolgen).
   3. Danach das eigentliche, von der CA signierte Zertifikat ueber
      'Signiertes Zertifikat einspielen' fuer dasselbe Label ('$tls_label') einspielen.
================================================================================
EOF
            ;;
        TRUST)
            if [[ "$kdb_exists" != "yes" ]]; then
                die "Kein Key-Repository fuer '$target_qm' vorhanden. Bitte zuerst 'Self-Signed' oder 'CSR' waehlen."
            fi
            local src_file; src_file="$(ask 'Pfad zur CA-Zertifikatsdatei (Root oder Zwischenzertifikat, PEM/.cer/.crt)' '')"
            [[ -f "$src_file" ]] || die "Datei nicht gefunden: $src_file"
            local trust_label; trust_label="$(ask 'Label fuer dieses Trust-Zertifikat' 'ca-root')"
            local dst_file="${ssldir}/$(basename "$src_file")"
            cp "$src_file" "$dst_file" && chown mqm:mqm "$dst_file" 2>/dev/null \
                || die "Kopieren der Zertifikatsdatei nach '$ssldir' fehlgeschlagen."
            su -s /bin/bash mqm -c "runmqakm -cert -add -db '$kdb_file' -stashed -label '$trust_label' -file '$dst_file' -format ascii" >>"$LOGFILE" 2>&1 \
                || die "Hinzufuegen des Trust-Zertifikats '$trust_label' fehlgeschlagen."
            info "Trust-Zertifikat '$trust_label' zu '$target_qm' hinzugefuegt."
            ;;
        RECEIVE)
            if [[ "$kdb_exists" != "yes" ]]; then
                die "Kein Key-Repository fuer '$target_qm' vorhanden. Bitte zuerst per CSR ein Zertifikat anfordern."
            fi
            local src_file; src_file="$(ask 'Pfad zur von der CA signierten Zertifikatsdatei' '')"
            [[ -f "$src_file" ]] || die "Datei nicht gefunden: $src_file"
            local dst_file="${ssldir}/$(basename "$src_file")"
            cp "$src_file" "$dst_file" && chown mqm:mqm "$dst_file" 2>/dev/null \
                || die "Kopieren der Zertifikatsdatei nach '$ssldir' fehlgeschlagen."
            su -s /bin/bash mqm -c "runmqakm -cert -receive -db '$kdb_file' -stashed -file '$dst_file'" >>"$LOGFILE" 2>&1 \
                || die "Einspielen des signierten Zertifikats fehlgeschlagen. Pruefen: sind die Root-/Zwischenzertifikate der CA bereits als vertrauenswuerdig hinzugefuegt (Menuepunkt 'Trust-Zertifikat hinzufuegen')?"
            info "Signiertes Zertifikat fuer '$target_qm' erfolgreich eingespielt."
            local tls_label; tls_label="$(ask 'Label des soeben empfangenen Zertifikats (fuer CERTLABL)' "qm.${target_qm,,}")"
            su -s /bin/bash mqm -c "echo \"ALTER QMGR SSLKEYR('$keydb') CERTLABL('$tls_label')
REFRESH SECURITY TYPE(SSL)\" | runmqsc '$target_qm'" >>"$LOGFILE" 2>&1 \
                || warn "ALTER QMGR/REFRESH SECURITY meldete Probleme - bitte manuell pruefen."
            info "SSLKEYR/CERTLABL fuer '$target_qm' gesetzt und Security-Cache aktualisiert."
            ;;
        LIST)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "Kein Key-Repository fuer '$target_qm' vorhanden (TLS wurde fuer diesen QM noch nicht eingerichtet)."
                warn "Bitte zuerst 'Self-Signed-Zertifikat erstellen' oder 'CSR fuer eine echte CA erstellen' waehlen."
            else
                local out; out="$(su -s /bin/bash mqm -c "runmqakm -cert -list -db '$kdb_file' -stashed" 2>&1)" || true
                echo "$out" | tee -a "$LOGFILE"
                if [[ "$UI_MODE" == "tui" ]]; then
                    read -r rows cols <<< "$(ui_dims)"
                    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Zertifikate in $target_qm" \
                        --msgbox "${out:-Keine Zertifikate gefunden.}" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
                fi
            fi
            ;;
        DETAILS)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "Kein Key-Repository fuer '$target_qm' vorhanden (TLS wurde fuer diesen QM noch nicht eingerichtet)."
                warn "Bitte zuerst 'Self-Signed-Zertifikat erstellen' oder 'CSR fuer eine echte CA erstellen' waehlen."
            else
                local label; label="$(ask 'Label des Zertifikats' "qm.${target_qm,,}")"
                local out; out="$(su -s /bin/bash mqm -c "runmqakm -cert -details -db '$kdb_file' -stashed -label '$label'" 2>&1)" || true
                echo "$out" | tee -a "$LOGFILE"
                if [[ "$UI_MODE" == "tui" ]]; then
                    read -r rows cols <<< "$(ui_dims)"
                    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Zertifikat-Details: $label" \
                        --msgbox "${out:-Kein Zertifikat mit diesem Label gefunden.}" "$rows" "$cols" 3>&1 1>&2 2>&3 || true
                fi
            fi
            ;;
        PASSWORD)
            if [[ "$kdb_exists" != "yes" ]]; then
                warn "Kein Key-Repository fuer '$target_qm' vorhanden (TLS wurde fuer diesen QM noch nicht eingerichtet)."
                warn "Bitte zuerst 'Self-Signed-Zertifikat erstellen' oder 'CSR fuer eine echte CA erstellen' waehlen."
            else
                narrate "Hinweis: Falls das aktuelle Passwort automatisch generiert und nicht bekannt ist,"
                narrate "kann es hier nicht geaendert werden - dann stattdessen Repository neu anlegen."
                local old_pw; old_pw="$(ask_secret 'Aktuelles Passwort des Key-Repository' '')"
                local new_pw; new_pw="$(ask_secret 'Neues Passwort' '')"
                su -s /bin/bash mqm -c "runmqakm -keydb -changepw -db '$kdb_file' -pw '$old_pw' -new_pw '$new_pw' -stash" >>"$LOGFILE" 2>&1 \
                    || die "Aendern des Passworts fuer '$target_qm' fehlgeschlagen (falsches aktuelles Passwort?). Logfile pruefen: $LOGFILE"
                info "Passwort des Key-Repository fuer '$target_qm' geaendert (neu gestasht, 'CSR'/'Self-Signed' etc. funktionieren weiterhin ohne erneute Passworteingabe)."
            fi
            ;;
    esac
}

run_main_flow() {
# Eigene PID (nicht $$, das in manchen Bash-Versionen in Subshells weiterhin
# die PID der obersten Shell liefert) fuer cancel_to_menu()'s Signal-Mechanismus
# hinterlegen, plus Trap: ein empfangenes USR1-Signal beendet DIESE Subshell
# sofort mit Code 99, unabhaengig davon, wie tief sie gerade in verschachtelten
# Command-Substitutionen (z. B. "X=\"\$(ask ...)\"") haengt.
RUN_MAIN_FLOW_PID=$BASHPID
trap 'exit 99' USR1
main_menu

# Fuer die Modi "install"/"upgrade"/"feature" ist das Installationsmedium zwingend
# erforderlich; ist es (noch) nicht per --media gesetzt, wird es interaktiv abgefragt.
if [[ "$MODE" =~ ^(install|upgrade|feature)$ ]]; then
    ensure_media_path "$MODE"
fi

# Upgrade, Feature-Installation, Backup und Restore sind eigenstaendige Ablaeufe,
# die nicht die QM-Neuanlage/-Provisionierung durchlaufen: hier abzweigen und beenden.
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
# 5d) Konsolidierte Auswahl-Dialoge fuer Security-Features und Komponenten
#-------------------------------------------------------------------------------
# Whiptail-Checklisten geben ausgewaehlte Tags space-getrennt zurueck (unsere
# Tags enthalten keine Leerzeichen, daher kein Quoting zu erwarten).
select_security_features() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        return 0  # Werte kommen unveraendert aus den Umgebungsvariablen/Defaults
    fi

    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        # WICHTIG: --separate-output liefert einen Tag pro Zeile OHNE Anfuehrungszeichen.
        # Ohne diese Option quotiert whiptail/dialog jeden Tag (z. B. "CONNAUTH"), was
        # den anschliessenden case-Vergleich sonst nie treffen wuerde (Bug: immer "no").
        # Das "|| { ...; return 1; }" muss direkt an der Zuweisung haengen, da ein
        # spaeteres "if [[ $? -ne 0 ]]" unter 'set -e' nie erreicht wuerde.
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Standard-Security-Features" \
            --cancel-button "Zurueck" \
            --checklist "Mit LEERTASTE an-/abwaehlen, mit ENTER bestaetigen.\n(Abbrechen = zurueck zum Hauptmenue)" "$rows" "$cols" 4 \
            --separate-output \
            "CONNAUTH"  "Connection Authentication (User/Passwort erzwingen)"       "$( [[ "$SEC_CONNAUTH" == "yes" ]] && echo on || echo off )" \
            "CHLAUTH"   "Channel Authentication Records aktiv lassen"              "$( [[ "$SEC_CHLAUTH" == "yes" ]] && echo on || echo off )" \
            "BLOCKPRIV" "Privilegierte Benutzer auf Kanaelen blocken"              "$( [[ "$SEC_BLOCK_PRIV" == "yes" ]] && echo on || echo off )" \
            "TLS"       "TLS einrichten (Key-Repository + Self-Signed-Zertifikat)" "$( [[ "$SEC_TLS" == "yes" ]] && echo on || echo off )" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch (Security-Features)."
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
        # Text-Fallback: nummeriertes Umschalt-Menue statt Einzel-Ja/Nein-Fragen
        info "==== Standard-Security-Features ===="
        while true; do
            echo "  1) [$( [[ "$SEC_CONNAUTH" == "yes" ]] && echo x || echo ' ' )] Connection Authentication (User/Passwort erzwingen)"
            echo "  2) [$( [[ "$SEC_CHLAUTH" == "yes" ]] && echo x || echo ' ' )] Channel Authentication Records aktiv lassen"
            echo "  3) [$( [[ "$SEC_BLOCK_PRIV" == "yes" ]] && echo x || echo ' ' )] Privilegierte Benutzer auf Kanaelen blocken"
            echo "  4) [$( [[ "$SEC_TLS" == "yes" ]] && echo x || echo ' ' )] TLS einrichten (Key-Repository + Self-Signed-Zertifikat)"
            local sel
            read -r -p "Nummer zum Umschalten, 'f' fortfahren, 'z' zurueck zum Hauptmenue [f]: " sel < /dev/tty || true
            case "${sel:-f}" in
                1) [[ "$SEC_CONNAUTH" == "yes" ]] && SEC_CONNAUTH="no" || SEC_CONNAUTH="yes" ;;
                2) [[ "$SEC_CHLAUTH" == "yes" ]] && SEC_CHLAUTH="no" || SEC_CHLAUTH="yes" ;;
                3) [[ "$SEC_BLOCK_PRIV" == "yes" ]] && SEC_BLOCK_PRIV="no" || SEC_BLOCK_PRIV="yes" ;;
                4) [[ "$SEC_TLS" == "yes" ]] && SEC_TLS="no" || SEC_TLS="yes" ;;
                z|Z) cancel_to_menu "Abbruch (Security-Features)." ;;
                f|F|"") break ;;
                *) warn "Ungueltige Eingabe." ;;
            esac
        done
    fi
    narrate "Security-Features: CONNAUTH=$SEC_CONNAUTH CHLAUTH=$SEC_CHLAUTH BLOCKPRIV=$SEC_BLOCK_PRIV TLS=$SEC_TLS"
    return 0
}

select_optional_components() {
    if [[ "$NON_INTERACTIVE" == "yes" ]]; then
        return 0  # Werte kommen unveraendert aus den Umgebungsvariablen/Defaults
    fi

    if [[ "$UI_MODE" == "tui" ]]; then
        read -r rows cols <<< "$(ui_dims)"
        local sel
        sel="$("$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Optionale Komponenten" \
            --cancel-button "Zurueck" \
            --checklist "Mit LEERTASTE an-/abwaehlen, mit ENTER bestaetigen.\n(Abbrechen = zurueck zu Security-Features)" "$rows" "$cols" 4 \
            --separate-output \
            "AMS"       "Advanced Message Security (AMS) installieren"                       "$( [[ "$SEC_AMS" == "yes" ]] && echo on || echo off )" \
            "WEB"       "MQ Web Console installieren"                                        "$( [[ "$INST_WEB" == "yes" ]] && echo on || echo off )" \
            "AUTOSTART" "systemd-Autostart fuer die Queue Manager einrichten"                 "$( [[ "$ENABLE_AUTOSTART" == "yes" ]] && echo on || echo off )" \
            "ALIASES"   "Bequemlichkeits-Aliase anlegen (tail-/mqsc-/status-<qm> usw.)"        "$( [[ "$ENABLE_ALIASES" == "yes" ]] && echo on || echo off )" \
            3>&1 1>&2 2>&3)" || cancel_to_menu "Abbruch (Optionale Komponenten)."
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
        info "==== Optionale Komponenten ===="
        while true; do
            echo "  1) [$( [[ "$SEC_AMS" == "yes" ]] && echo x || echo ' ' )] Advanced Message Security (AMS) installieren"
            echo "  2) [$( [[ "$INST_WEB" == "yes" ]] && echo x || echo ' ' )] MQ Web Console installieren"
            echo "  3) [$( [[ "$ENABLE_AUTOSTART" == "yes" ]] && echo x || echo ' ' )] systemd-Autostart fuer die Queue Manager einrichten"
            echo "  4) [$( [[ "$ENABLE_ALIASES" == "yes" ]] && echo x || echo ' ' )] Bequemlichkeits-Aliase anlegen (tail-/mqsc-/status-<qm> usw.)"
            local sel
            read -r -p "Nummer zum Umschalten, 'f' fortfahren, 'z' zurueck [f]: " sel < /dev/tty || true
            case "${sel:-f}" in
                1) [[ "$SEC_AMS" == "yes" ]] && SEC_AMS="no" || SEC_AMS="yes" ;;
                2) [[ "$INST_WEB" == "yes" ]] && INST_WEB="no" || INST_WEB="yes" ;;
                3) [[ "$ENABLE_AUTOSTART" == "yes" ]] && ENABLE_AUTOSTART="no" || ENABLE_AUTOSTART="yes" ;;
                4) [[ "$ENABLE_ALIASES" == "yes" ]] && ENABLE_ALIASES="no" || ENABLE_ALIASES="yes" ;;
                z|Z) cancel_to_menu "Abbruch (Optionale Komponenten)." ;;
                f|F|"") break ;;
                *) warn "Ungueltige Eingabe." ;;
            esac
        done
    fi
    narrate "Optionale Komponenten: AMS=$SEC_AMS WEB=$INST_WEB AUTOSTART=$ENABLE_AUTOSTART ALIASES=$ENABLE_ALIASES"
    return 0
}

#-------------------------------------------------------------------------------
# 6) Interaktive Parameter-Abfrage
#-------------------------------------------------------------------------------
gather_parameters() {
    echo
    narrate "==== MQ-Parameter ===="

    # --- Queue Manager (1..x) bestimmen ---
    if [[ -n "$MQ_QMGRS" ]]; then
        # Vorgegebene Spezifikation parsen: NAME:PORT:CHANNEL,...
        parse_qmgr_spec "$MQ_QMGRS"
        narrate "Queue-Manager aus MQ_QMGRS uebernommen (${#QMGR_NAMES[@]} Stueck)."
    elif [[ "$NON_INTERACTIVE" == "yes" ]]; then
        # Rueckwaertskompatibel: einzelner QM aus den Einzelvariablen
        QMGR_NAMES=("$MQ_QMGR_NAME"); QMGR_PORTS=("$MQ_LISTENER_PORT"); QMGR_CHANNELS=("$MQ_APP_CHANNEL")
    else
        local count
        count="$(ask 'Wie viele Queue Manager sollen angelegt werden?' '1')"
        [[ "$count" =~ ^[0-9]+$ && "$count" -ge 1 ]] || count=1
        local i name port chan defname defport
        for (( i=1; i<=count; i++ )); do
            echo
            narrate "--- Queue Manager $i von $count ---"
            if [[ $i -eq 1 ]]; then defname="$MQ_QMGR_NAME"; defport="$MQ_LISTENER_PORT"
            else defname="QM${i}"; defport=$(( 1413 + i )); fi
            name="$(ask "  Name des QM $i" "$defname")"
            port="$(ask "  Listener-Port fuer '$name'" "$defport")"
            chan="$(ask "  Anwendungs-Kanal (SVRCONN) fuer '$name'" "$MQ_APP_CHANNEL")"
            QMGR_NAMES+=("$name"); QMGR_PORTS+=("$port"); QMGR_CHANNELS+=("$chan")
        done
    fi
    # Erste Werte als "Haupt-QM" fuer abhaengige Defaults (z. B. Zert-DN) spiegeln
    MQ_QMGR_NAME="${QMGR_NAMES[0]}"
    MQ_LISTENER_PORT="${QMGR_PORTS[0]}"
    MQ_APP_CHANNEL="${QMGR_CHANNELS[0]}"

    echo
    MQ_APP_USER="$(ask 'Nicht-privilegierter Anwendungs-Benutzer (fuer alle QMs)' "$MQ_APP_USER")"
    MQ_APP_GROUP="$(ask 'OS-Gruppe fuer Berechtigungen (statt einzeln je Benutzer)' "$MQ_APP_GROUP")"
    MQ_EXPLORER_CHANNEL="$(ask 'Dedizierter Kanal NUR fuer MQ Explorer/Admin-Tools (getrennt vom App-Kanal, fuer alle QMs)' "$MQ_EXPLORER_CHANNEL")"
    MQ_APP_QUEUE="$(ask 'Beispiel-Anwendungsqueue je QM (leer = keine)' "$MQ_APP_QUEUE")"
    MQ_DLQ="$(ask 'Dead Letter Queue (Name)' "$MQ_DLQ")"
    MQ_LOG_TYPE="$(ask 'Logging-Typ (circular/linear)' "$MQ_LOG_TYPE")"
    MQ_LOG_PRIMARY="$(ask 'Primaer-Log-Groesse in 4K-Bloecken (default 4096)' "$MQ_LOG_PRIMARY")"
    if [[ "$MQ_LOG_TYPE" == "linear" ]]; then
        MQ_LOG_SECONDARY="$(ask 'Sekundaer-Log-Groesse in 4K-Bloecken (default 1024)' "$MQ_LOG_SECONDARY")"
    fi

    echo
    narrate "==== Weitere gaengige QM-Parameter ===="
    MQ_MAXMSGL="$(ask 'Max. Nachrichtenlaenge in Byte (MAXMSGL)' "$MQ_MAXMSGL")"
    MQ_MAXCHL="$(ask 'Max. Anzahl definierter Kanaele (MAXCHL)' "$MQ_MAXCHL")"
    MQ_MAXACTCHL="$(ask 'Max. Anzahl gleichzeitig aktiver Kanaele (MAXACTCHL)' "$MQ_MAXACTCHL")"
    MQ_DESCR="$(ask 'Beschreibung des Queue Managers (DESCR, optional)' "$MQ_DESCR")"

    # ---- Security-Features / Optionale Komponenten / Details / Zusammenfassung ----
    # Schrittkette mit Zurueck-Navigation:
    #   WSTEP=1 Security-Features   (Abbrechen -> cancel_to_menu(), direkt zurueck zum Hauptmenue)
    #   WSTEP=2 Optionale Komponenten (Abbrechen -> zurueck zu WSTEP=1)
    #   WSTEP=3 TLS/Web-Details + Zusammenfassung
    #           ("Nein" bei der Bestaetigung -> zurueck zu WSTEP=1 zum Anpassen)
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
                    TLS_CERT_DN="$(ask 'Zertifikat-DN' "CN=${MQ_QMGR_NAME},O=Example,C=DE")"
                fi

                # ---- MQ Web Console: Benutzer/Passwort abfragen ----
                if [[ "$INST_WEB" == "yes" ]]; then
                    echo
                    narrate "==== MQ Web Console (Admin-Zugang) ===="
                    narrate "Hinweis: Dieser Benutzer existiert nur in der mqweb-Registry (kein OS-Konto noetig)."
                    WEB_ADMIN_USER="$(ask 'Web-Admin-Benutzername' "$WEB_ADMIN_USER")"
                    WEB_ADMIN_PASS="$(ask_secret 'Web-Admin-Passwort' "$WEB_ADMIN_PASS")"
                    if [[ "$(ask_yes_no 'Zusaetzlichen Nur-Lese-Benutzer (MQWebAdminRO) anlegen?' 'no')" == "yes" ]]; then
                        WEB_RO_USER="$(ask 'Nur-Lese-Benutzername' "${WEB_RO_USER:-mqreader}")"
                        WEB_RO_PASS="$(ask_secret 'Nur-Lese-Passwort' "$WEB_RO_PASS")"
                    fi
                    WEB_REMOTE="$(ask_yes_no 'Remote-Zugriff auf die Console erlauben (alle Interfaces)?' "$WEB_REMOTE")"
                    WEB_HTTPS_PORT="$(ask 'HTTPS-Port der Console' "$WEB_HTTPS_PORT")"
                fi

                echo
                narrate "==== Zusammenfassung ===="
                local summary_text
                summary_text="$( {
                    echo "Queue Manager (${#QMGR_NAMES[@]}):"
                    local k
                    for k in "${!QMGR_NAMES[@]}"; do
                        printf "  - %-12s Port %-6s Kanal %s\n" \
                            "${QMGR_NAMES[$k]}" "${QMGR_PORTS[$k]}" "${QMGR_CHANNELS[$k]}"
                    done
                    cat <<EOF

App-Benutzer     : $MQ_APP_USER (Gruppe: $MQ_APP_GROUP)
App-Queue je QM  : ${MQ_APP_QUEUE:-<keine>}
Dead Letter Queue: $MQ_DLQ
Logging          : $MQ_LOG_TYPE (primaer $MQ_LOG_PRIMARY, sekundaer $MQ_LOG_SECONDARY)
MAXMSGL / MAXCHL / MAXACTCHL : $MQ_MAXMSGL / $MQ_MAXCHL / $MQ_MAXACTCHL
Beschreibung     : ${MQ_DESCR:-<keine>}
CONNAUTH         : $SEC_CONNAUTH
CHLAUTH          : $SEC_CHLAUTH
Block privileged : $SEC_BLOCK_PRIV
TLS              : $SEC_TLS
AMS              : $SEC_AMS
Web Console      : $INST_WEB$( [[ "$INST_WEB" == "yes" ]] && echo " (Admin: $WEB_ADMIN_USER, Port $WEB_HTTPS_PORT, Remote: $WEB_REMOTE)" )
Autostart        : $ENABLE_AUTOSTART
Aliase           : $ENABLE_ALIASES
EOF
                } )"
                if [[ "$UI_MODE" == "tui" ]]; then
                    # Im TUI-Modus nur ins Logfile schreiben (nicht aufs Terminal),
                    # die eigentliche Anzeige uebernimmt die ui_summary_box gleich danach.
                    echo "$summary_text" >> "$LOGFILE"
                    ui_summary_box "Zusammenfassung" "$summary_text"
                else
                    echo "$summary_text" | tee -a "$LOGFILE"
                fi
                if [[ "$(ask_yes_no 'Mit diesen Einstellungen fortfahren?' 'yes')" == "yes" ]]; then
                    break   # fertig – gather_parameters erfolgreich abgeschlossen
                else
                    info "Zurueck zu den Security-/Komponenten-Einstellungen ..."
                    WSTEP=1
                fi
                ;;
        esac
    done
    return 0
}
gather_parameters

#-------------------------------------------------------------------------------
# 7-10) Software-Installation (nur im Modus "install"; "addqm" nutzt bestehende MQ-Umgebung)
#-------------------------------------------------------------------------------
# Hinweis: prepare_media(), accept_license() und post_install_setup() sind
# bereits weiter oben (Abschnitt 5b, vor main_menu) definiert, damit sie auch
# von perform_upgrade()/perform_feature_install() wiederverwendet werden koennen.
install_rpm_packages() {
    narrate "Installiere RPM-Pakete ..."
    # Reihenfolge: Runtime zuerst. Server, GSKit (TLS), SDK, Samples, JRE/Java.
    local pkgs=( MQSeriesRuntime MQSeriesServer MQSeriesGSKit MQSeriesSDK MQSeriesSamples MQSeriesMan )
    [[ "$SEC_TLS" == "yes" || "$SEC_AMS" == "yes" || "$INST_WEB" == "yes" ]] && pkgs+=( MQSeriesJRE MQSeriesJava )
    [[ "$SEC_AMS" == "yes" ]]  && pkgs+=( MQSeriesAMS )
    [[ "$INST_WEB" == "yes" ]] && pkgs+=( MQSeriesWeb )

    local files=()
    for p in "${pkgs[@]}"; do
        local f
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${p}-*.rpm" | head -n1 || true)"
        if [[ -n "$f" ]]; then files+=( "$f" ); else warn "Paket nicht gefunden (uebersprungen): $p"; fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "Keine RPM-Pakete gefunden."

    # rpm -ivh installiert in der angegebenen Reihenfolge mit Abhaengigkeitspruefung.
    # --oldpackage/--replacepkgs nur bei erzwungener Neuinstallation ueber bestehende Pakete.
    local rpm_flags=(-ivh)
    [[ "$FORCE_REINSTALL" == "yes" ]] && rpm_flags=(-ivh --oldpackage --replacepkgs --replacefiles)
    run_with_progress "Installiere ${#files[@]} RPM-Paket(e) (kann 1-2 Minuten dauern) ..." \
        rpm "${rpm_flags[@]}" "${files[@]}" || die "RPM-Installation fehlgeschlagen. Logfile pruefen: $LOGFILE"
    info "RPM-Pakete installiert."
}

install_deb_packages() {
    narrate "Installiere DEB-Pakete ..."
    local pkgs=( ibmmq-runtime ibmmq-server ibmmq-gskit ibmmq-sdk ibmmq-samples ibmmq-man )
    [[ "$SEC_TLS" == "yes" || "$SEC_AMS" == "yes" || "$INST_WEB" == "yes" ]] && pkgs+=( ibmmq-jre ibmmq-java )
    [[ "$SEC_AMS" == "yes" ]]  && pkgs+=( ibmmq-ams )
    [[ "$INST_WEB" == "yes" ]] && pkgs+=( ibmmq-web )

    local files=()
    for p in "${pkgs[@]}"; do
        local f
        f="$(find "$MQ_SRC" -maxdepth 1 -name "${p}_*.deb" | head -n1 || true)"
        if [[ -n "$f" ]]; then files+=( "$f" ); else warn "Paket nicht gefunden (uebersprungen): $p"; fi
    done
    [[ ${#files[@]} -gt 0 ]] || die "Keine DEB-Pakete gefunden."

    export DEBIAN_FRONTEND=noninteractive
    # apt loest lokale Inter-Abhaengigkeiten der uebergebenen .deb auf.
    # --allow-downgrades/--allow-remove-essential nur bei erzwungener Neuinstallation.
    local apt_flags=(-y install)
    [[ "$FORCE_REINSTALL" == "yes" ]] && apt_flags=(-y --allow-downgrades install)
    run_with_progress "Installiere ${#files[@]} DEB-Paket(e) (kann 1-2 Minuten dauern) ..." \
        apt-get "${apt_flags[@]}" "${files[@]}" || die "DEB-Installation fehlgeschlagen. Logfile pruefen: $LOGFILE"
    info "DEB-Pakete installiert."
}

install_mq_software() {
    prepare_media
    accept_license

    local _existing_check
    _existing_check="$(check_existing_mq_packages)"
    info "Pruefung auf bestehende IBM-MQ-Pakete (Paketformat: $PKG_FORMAT): Ergebnis='$_existing_check'"
    if [[ "$_existing_check" == "yes" ]]; then
        local installed_ver media_ver
        installed_ver="$(get_installed_mq_version)"
        media_ver="$(get_media_mq_version)"
        info "Installierte Version: ${installed_ver:-unbekannt}  |  Medien-Version: ${media_ver:-unbekannt}"

        if [[ "$(would_be_real_downgrade "$installed_ver" "$media_ver")" == "yes" ]]; then
            warn "ACHTUNG: Die installierten IBM-MQ-Pakete (Version $installed_ver) sind NEUER als diese"
            warn "Medien (Version $media_ver). IBM MQ unterstuetzt KEIN Downgrade auf eine niedrigere"
            warn "Version/Release/Modification-Ebene - das Paket-Installationsskript von IBM selbst"
            warn "verweigert dies (Fehler 'Downgrading ... is not supported'), unabhaengig von"
            warn "apt/rpm-Optionen wie --allow-downgrades. Ein Erzwingen ist NICHT moeglich."
            die "Abbruch: echtes Downgrade ($installed_ver -> $media_ver) wird von IBM MQ nicht unterstuetzt. Optionen: (1) Installationsmedien mit Version >= $installed_ver verwenden, oder (2) die bestehende Installation vollstaendig entfernen (z. B. 'apt purge ibmmq*' bzw. 'rpm -e' aller MQSeries*-Pakete, danach Reste in /var/mqm/qmgrs und /var/mqm/log pruefen) und danach erneut installieren."
        fi

        warn "Auf diesem Host sind bereits IBM-MQ-Pakete installiert."
        warn "'Neuinstallation' ist fuer einen frischen Host gedacht. Wird trotzdem fortgefahren,"
        warn "kann apt/rpm vorhandene Pakete auf die Version dieser Medien AKTUALISIEREN/NEU INSTALLIEREN"
        warn "und dabei Komponenten, die in diesem Lauf nicht ausgewaehlt sind (z. B. AMQP, AMS,"
        warn "Client-Tools, File Transfer, MQTT/Telemetry, Sprachpakete), vollstaendig ENTFERNEN."
        warn "Empfohlen: Hauptmenue -> 'Upgrade' (aktualisiert kontrolliert, entfernt nichts) oder"
        warn "'Zusatzfeature nachinstallieren' oder 'Weiteren Queue Manager hinzufuegen' verwenden."
        local proceed="$FORCE_REINSTALL"
        if [[ -z "$proceed" ]]; then
            proceed="$(ask_yes_no 'Bestehende IBM-MQ-Installation erkannt. Trotzdem mit der Neuinstallation fortfahren (kann Pakete aendern/entfernen)?' 'no')"
        fi
        if [[ "$proceed" != "yes" ]]; then
            cancel_to_menu "Abbruch: bestehende IBM-MQ-Installation erkannt. Bitte 'Upgrade', 'Weiteren Queue Manager hinzufuegen' oder 'Zusatzfeature nachinstallieren' im Hauptmenue waehlen (oder MQ_MODE entsprechend setzen)."
        fi
        FORCE_REINSTALL="yes"
        warn "Fortfahren mit erzwungener Neuinstallation (--allow-downgrades / --oldpackage aktiv) ..."
    fi

    ui_menu_intro "Installiere IBM MQ Pakete ($PKG_FORMAT)"
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
    info "Modus 'addqm': ueberspringe Paketinstallation, nutze bestehende Installation unter '$MQ_INSTALL_PATH'."
    source_mqenv
    info "IBM MQ Version (bestehende Installation):"
    dspmqver | tee -a "$LOGFILE"
    MQ_INSTALLED_VERSION="$(dspmqver 2>/dev/null | awk -F': *' '/^Version/{print $2; exit}')" || true
fi

#-------------------------------------------------------------------------------
# 11) Benutzer/Gruppen-Best-Practice
#-------------------------------------------------------------------------------
# Stellt sicher, dass ein einzelner sysctl-Parameter MINDESTENS den
# IBM-empfohlenen Wert hat - hebt ihn nur an, senkt NIE einen bereits
# hoeheren (besseren) Wert ab. Gibt den resultierenden (finalen) Wert aus.
sysctl_ensure_min() {
    local param="$1" min_val="$2"
    local current; current="$(sysctl -n "$param" 2>/dev/null)" || current=""
    if [[ "$current" =~ ^[0-9]+$ ]] && [[ "$current" -ge "$min_val" ]]; then
        narrate "  $param = $current (bereits >= IBM-Minimum $min_val, unveraendert)"
        echo "$current"
    else
        narrate "  $param: '${current:-unbekannt}' -> $min_val (auf IBM-Minimum angehoben)"
        echo "$min_val"
    fi
}

# Setzt IBM-dokumentierte Kernel-Parameter und ulimits fuer MQ (siehe IBM-Doku
# "Configuring the operating system on Linux"). Alle Werte sind MINDESTWERTE -
# ein bereits hoeherer/besserer bestehender Wert wird nie abgesenkt. Zusaetzlich
# werden LimitNOFILE/LimitNPROC in die QM-systemd-Units eingetragen, da PAM-
# basierte ulimits (limits.conf) bei per systemd gestarteten Diensten laut
# IBM-Doku NICHT greifen.
tune_os_for_mq() {
    local proceed="$OS_TUNE_MQ"
    if [[ -z "$proceed" ]]; then
        proceed="$(ask_yes_no 'IBM-empfohlene Kernel-/Limits-Tuning-Werte fuer MQ setzen (nur anheben, nie absenken)?' 'yes')"
    fi
    if [[ "$proceed" != "yes" ]]; then
        info "OS-Tuning fuer MQ uebersprungen (Benutzerwunsch)."
        return 0
    fi
    info "Pruefe/setze IBM-empfohlene Kernel-Parameter fuer MQ ..."

    local shmmni shmall shmmax filemax pidmax threadsmax
    shmmni="$(sysctl_ensure_min kernel.shmmni 4096)"
    shmall="$(sysctl_ensure_min kernel.shmall 2097152)"
    shmmax="$(sysctl_ensure_min kernel.shmmax 268435456)"
    filemax="$(sysctl_ensure_min fs.file-max 524288)"
    # IBM-Doku nennt 120000 (nicht 12000 - in manchen kopierten Vorlagen
    # fehlt eine Null; 12000 waere auf modernen Systemen oft eine Verschlechterung)
    pidmax="$(sysctl_ensure_min kernel.pid_max 120000)"
    threadsmax="$(sysctl_ensure_min kernel.threads-max 48000)"

    # kernel.sem hat 4 Werte (SEMMSL SEMMNS SEMOPM SEMMNI) - jeden einzeln
    # nur anheben, IBM-Minimum: 500 256000 250 1024
    local sem_current sem_min=(500 256000 250 1024) sem_out=()
    sem_current="$(sysctl -n kernel.sem 2>/dev/null)" || sem_current="0 0 0 0"
    local -a sem_cur_a=($sem_current)
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
        narrate "  kernel.sem: '$sem_current' -> '$sem_final' (einzelne Werte auf IBM-Minimum angehoben)"
    else
        narrate "  kernel.sem = '$sem_current' (bereits >= IBM-Minimum, unveraendert)"
    fi

    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-ibmmq.conf <<EOF
# IBM MQ empfohlene Kernel-Parameter (automatisch gesetzt von install-ibmmq-9.4.sh)
# Werden nur angehoben, nie unter einen bereits besseren Wert abgesenkt.
kernel.shmmni = $shmmni
kernel.shmall = $shmall
kernel.shmmax = $shmmax
kernel.sem = $sem_final
fs.file-max = $filemax
kernel.pid_max = $pidmax
kernel.threads-max = $threadsmax
EOF
    sysctl -p /etc/sysctl.d/99-ibmmq.conf >>"$LOGFILE" 2>&1 \
        || warn "sysctl -p meldete Probleme (z. B. in Containern mit read-only /proc) - Logfile pruefen."
    info "Kernel-Parameter in /etc/sysctl.d/99-ibmmq.conf gesetzt und angewendet."

    # ulimits fuer mqm/root - gelten fuer normale Logins/PAM-Sessions.
    mkdir -p /etc/security/limits.d
    cat > /etc/security/limits.d/99-ibmmq.conf <<EOF
# IBM MQ empfohlene Ressourcen-Limits (automatisch gesetzt von install-ibmmq-9.4.sh)
mqm             hard    nofile          $MQ_NOFILE_LIMIT
mqm             soft    nofile          $MQ_NOFILE_LIMIT
mqm             hard    nproc           $MQ_NPROC_LIMIT
mqm             soft    nproc           $MQ_NPROC_LIMIT
root            hard    nofile          $MQ_NOFILE_LIMIT
root            soft    nofile          $MQ_NOFILE_LIMIT
EOF
    info "Ressourcen-Limits in /etc/security/limits.d/99-ibmmq.conf gesetzt (wirksam ab der naechsten Anmeldung/Session)."
    narrate "Hinweis: PAM-Limits (limits.conf) gelten NICHT fuer per systemd gestartete Queue Manager -"
    narrate "dafuer setzt dieses Script LimitNOFILE/LimitNPROC direkt in den QM-systemd-Units (siehe setup_autostart)."
}

setup_users() {
    info "Pruefe Benutzer/Gruppen ..."
    # 'mqm' wird durch die Pakete angelegt. Sicherheitshalber pruefen.
    getent group mqm >/dev/null || groupadd mqm
    id mqm >/dev/null 2>&1 || useradd -g mqm -d /var/mqm -s /usr/sbin/nologin mqm 2>/dev/null || true

    # Best Practice: dedizierter, NICHT privilegierter Anwendungs-User
    # (kein Mitglied von 'mqm' -> wird vom OAM als normaler User behandelt)
    if ! id "$MQ_APP_USER" >/dev/null 2>&1; then
        useradd -M -s /usr/sbin/nologin "$MQ_APP_USER" 2>/dev/null \
            || useradd -M -s /bin/false "$MQ_APP_USER"
        info "Anwendungs-Benutzer '$MQ_APP_USER' angelegt (nicht privilegiert)."
    else
        info "Anwendungs-Benutzer '$MQ_APP_USER' existiert bereits."
    fi
    if id -nG "$MQ_APP_USER" | grep -qw mqm; then
        warn "'$MQ_APP_USER' ist Mitglied von 'mqm' (= privilegiert). Best Practice: NICHT in 'mqm'."
    fi

    # Berechtigungs-Gruppe: setmqaut wird auf diese Gruppe vergeben statt auf
    # einzelne Benutzer (IBM Best Practice) - neue App-User oder MCAUSER
    # zusaetzlicher Kanaele muessen dann nur noch hier Mitglied werden,
    # statt jedes Mal erneut setmqaut auszufuehren.
    getent group "$MQ_APP_GROUP" >/dev/null || {
        groupadd "$MQ_APP_GROUP"
        info "Berechtigungsgruppe '$MQ_APP_GROUP' angelegt."
    }
    if ! id -nG "$MQ_APP_USER" | grep -qw "$MQ_APP_GROUP"; then
        usermod -aG "$MQ_APP_GROUP" "$MQ_APP_USER"
        info "'$MQ_APP_USER' zur Gruppe '$MQ_APP_GROUP' hinzugefuegt."
    fi
}
setup_users

#-------------------------------------------------------------------------------
# 12-15) Pro Queue Manager: anlegen, starten, TLS, Security-MQSC, Berechtigungen
#         provision_qmgr <name> <port> <channel>
#-------------------------------------------------------------------------------
provision_qmgr() {
    local qm="$1" port="$2" chan="$3"
    info "================ Queue Manager: $qm (Port $port, Kanal $chan) ================"

    # --- 12) Anlegen + starten ---
    if su -s /bin/bash mqm -c "dspmq" 2>/dev/null | grep -qw "QMNAME($qm)"; then
        warn "Queue Manager '$qm' existiert bereits – ueberspringe crtmqm."
    else
        local logopt="-lc"
        [[ "$MQ_LOG_TYPE" == "linear" ]] && logopt="-ll"
        su -s /bin/bash mqm -c "crtmqm $logopt -u '$MQ_DLQ' '$qm'" >>"$LOGFILE" 2>&1 \
            || die "crtmqm fuer '$qm' fehlgeschlagen."
        info "Queue Manager '$qm' angelegt."

        # MAXCHL/MAXACTCHL sind KEINE gueltigen ALTER QMGR-Parameter, sondern
        # werden in der qm.ini-Datei gesetzt (Stanza "Channels:"). Das muss
        # VOR dem ersten Start passieren, damit es sofort wirksam wird - bei
        # einem bereits laufenden/existierenden QM waere ein Neustart noetig,
        # daher nur hier im "frisch angelegt"-Zweig.
        if [[ -f "/var/mqm/qmgrs/${qm}/qm.ini" ]]; then
            info "Setze MAXCHL/MAXACTCHL fuer '$qm' in qm.ini (vor dem ersten Start) ..."
            {
                echo ""
                echo "Channels:"
                echo "   MaxChannels=$MQ_MAXCHL"
                echo "   MaxActiveChannels=$MQ_MAXACTCHL"
            } >> "/var/mqm/qmgrs/${qm}/qm.ini"
            chown mqm:mqm "/var/mqm/qmgrs/${qm}/qm.ini" 2>/dev/null || true
        else
            warn "qm.ini fuer '$qm' nicht gefunden - MAXCHL/MAXACTCHL konnten nicht gesetzt werden."
        fi
    fi
    start_qmgr_robust "$qm"

    # --- 13) TLS (optional, je QM eigenes Repository/Zertifikat) ---
    local tls_keyr="" tls_label=""
    if [[ "$SEC_TLS" == "yes" ]]; then
        local ssldir="/var/mqm/qmgrs/${qm}/ssl"
        local keydb="${ssldir}/key"
        tls_label="qm.${qm,,}"
        local dn_rest="${TLS_CERT_DN#*,}"          # alles nach dem ersten Komma
        [[ "$dn_rest" == "$TLS_CERT_DN" ]] && dn_rest="O=Example,C=DE"
        local cert_dn="CN=${qm},${dn_rest}"
        local tlspw; tlspw="$(openssl rand -base64 18 2>/dev/null || echo "Chg-Me-$(date +%s)")"
        su -s /bin/bash mqm -c "mkdir -p '$ssldir'"
        su -s /bin/bash mqm -c \
          "runmqakm -keydb -create -db '${keydb}.kdb' -pw '$tlspw' -type cms -stash" >>"$LOGFILE" 2>&1 \
          || die "runmqakm: Key-Repository fuer '$qm' fehlgeschlagen."
        su -s /bin/bash mqm -c \
          "runmqakm -cert -create -db '${keydb}.kdb' -stashed -label '$tls_label' \
             -dn '$cert_dn' -size 2048 -sig_alg SHA256WithRSA -expire 365" >>"$LOGFILE" 2>&1 \
          || die "runmqakm: Zertifikat fuer '$qm' fehlgeschlagen."
        tls_keyr="$keydb"
        info "TLS fuer '$qm': ${keydb}.kdb (Label $tls_label)"
    fi

    # --- 14) Security-MQSC erzeugen und anwenden ---
    local mqsc="${WORKDIR:-/tmp}/configure_${qm}.mqsc"
    # Einfache Anfuehrungszeichen im DESCR-Text fuer MQSC escapen ('->'')
    local descr_escaped="${MQ_DESCR//\'/\'\'}"
    {
        echo "* === Auto-generiert fuer $qm: $(date) ==="
        echo "* Gaengige QM-Parameter (MAXCHL/MAXACTCHL werden separat ueber qm.ini gesetzt,"
        echo "* da sie KEINE gueltigen ALTER QMGR-Parameter sind)"
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
            echo "* WARN: CHLAUTH deaktiviert – nicht empfohlen!"
        fi
        echo ""
        if [[ "$SEC_BLOCK_PRIV" == "yes" ]]; then
            echo "SET CHLAUTH('*') TYPE(BLOCKUSER) USERLIST('nobody','*MQADMIN') +"
            echo "    DESCR('Block privileged users') ACTION(REPLACE)"
            echo "SET CHLAUTH(SYSTEM.DEF.SVRCONN)   TYPE(BLOCKUSER) USERLIST('*MQADMIN') ACTION(REPLACE)"
            echo "SET CHLAUTH(SYSTEM.ADMIN.SVRCONN) TYPE(BLOCKUSER) USERLIST('*MQADMIN') ACTION(REPLACE)"
            echo ""
        fi
        echo "* Dedizierter Anwendungs-Kanal mit festem, nicht-privilegiertem MCAUSER"
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
            echo "    DESCR('Anwendungszugriff') ACTION(REPLACE)"
            echo ""
        fi
        # Separater, dedizierter Kanal NUR fuer MQ Explorer/Admin-Tools - bewusst
        # getrennt vom Anwendungs-Kanal, damit z. B. CHLAUTH-Regeln oder spaeteres
        # Deaktivieren/Einschraenken unabhaengig von der Anwendung erfolgen kann
        # (IBM Best Practice: Admin-/Tool-Zugriff nicht mit Anwendungszugriff mischen).
        echo "* Dedizierter Kanal NUR fuer MQ Explorer/Admin-Tools (getrennt von Anwendungen)"
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
            echo "    DESCR('MQ Explorer/Admin-Tool-Zugriff') ACTION(REPLACE)"
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

    # Per Pipe statt Datei-Redirection einspielen: die Datei liegt evtl. in
    # einem nur fuer root lesbaren WORKDIR (mktemp -d, Modus 0700) - "cat"
    # laeuft als root und kann sie lesen, "su ... runmqsc" empfaengt den
    # Inhalt dann einfach ueber die Standardeingabe (kein Datei-Open noetig).
    cat "$mqsc" | su -s /bin/bash mqm -c "runmqsc '$qm'" >>"$LOGFILE" 2>&1 \
        || die "runmqsc fuer '$qm' fehlgeschlagen. MQSC: $mqsc"
    cp "$mqsc" "/var/mqm/${qm}-configure.mqsc" 2>/dev/null || true
    info "Security-MQSC fuer '$qm' angewendet (Kopie: /var/mqm/${qm}-configure.mqsc)."

    # --- 15) Minimale Berechtigungen (Least Privilege) - auf die GRUPPE vergeben,
    #         nicht auf den einzelnen Benutzer (IBM Best Practice): weitere
    #         App-User/MCAUSER zusaetzlicher Kanaele muessen dann nur noch
    #         Mitglied dieser Gruppe werden, statt erneut setmqaut zu benoetigen.
    su -s /bin/bash mqm -c \
      "setmqaut -m '$qm' -t qmgr -g '$MQ_APP_GROUP' +connect +inq" >>"$LOGFILE" 2>&1 \
      || warn "setmqaut (qmgr) fuer '$qm' fehlgeschlagen."
    if [[ -n "$MQ_APP_QUEUE" ]]; then
        su -s /bin/bash mqm -c \
          "setmqaut -m '$qm' -n '$MQ_APP_QUEUE' -t queue -g '$MQ_APP_GROUP' +put +get +browse +inq" \
          >>"$LOGFILE" 2>&1 || warn "setmqaut (queue) fuer '$qm' fehlgeschlagen."
    fi
    info "Berechtigungen fuer '$qm' gesetzt (Least Privilege, Gruppe: $MQ_APP_GROUP)."
}

# Alle Queue Manager der Reihe nach bereitstellen
ui_menu_intro "Richte ${#QMGR_NAMES[@]} Queue Manager ein"
for _i in "${!QMGR_NAMES[@]}"; do
    provision_qmgr "${QMGR_NAMES[$_i]}" "${QMGR_PORTS[$_i]}" "${QMGR_CHANNELS[$_i]}"
done

#-------------------------------------------------------------------------------
# 14b) Bequemlichkeits-Aliase (tail-/mqsc-/status-/... je QM)
#-------------------------------------------------------------------------------
# Aliase statt Symlinks: kapseln den kompletten Befehl (inkl. Aufruf als
# 'mqm'-User bei runmqsc/dspmq/strmqm/endmqm) und sparen dadurch tatsaechlich
# Tipparbeit - ein reiner Pfad-Symlink tut das nicht. Wird bei JEDEM Lauf
# komplett neu aus ALLEN aktuell auf dem Host bekannten Queue Managern
# generiert (nicht nur den in diesem Lauf angelegten), damit bei einem
# spaeteren "Weiteren QM hinzufuegen" keine Aliase fuer bereits vorhandene
# QMs verloren gehen. Landet systemweit in /etc/profile.d/ (NICHT im
# .profile des 'mqm'-Users - der hat als Service-Account typischerweise
# 'nologin' als Shell, ein Login als 'mqm' findet also nie statt und wuerde
# ein dortiges .profile nie laden; die eigentlichen Nutzer sind die
# Admins, die sich per SSH/sudo einloggen).
setup_aliases() {
    [[ "$ENABLE_ALIASES" == "yes" ]] || return 0
    local all_qms; all_qms="$(get_all_qm_names)"
    [[ -n "$all_qms" ]] || return 0

    local afile="/etc/profile.d/mqm-aliases.sh"
    {
        echo "# IBM MQ Troubleshooting-/Admin-Aliase (automatisch generiert von install-ibmmq-9.4.sh)"
        echo "# Neu generiert bei jedem Lauf - manuelle Aenderungen gehen verloren."
        echo "# Uebersicht: tail-/mqsc-/status-/start-/stop-/chstatus-/qdepth-/xmitq-<qm>  sowie global: mqver, qmlist"
        local qm aname
        while IFS= read -r qm; do
            [[ -n "$qm" ]] || continue
            # Alias-Name: Kleinbuchstaben, alles ausser a-z0-9 wird zu '_'
            # (QM-Namen duerfen '.'/'-' enthalten, die in Alias-Namen nicht gehen)
            aname="$(printf '%s' "${qm,,}" | tr -c 'a-z0-9' '_')"
            # Aktuelles Error-Log verfolgen (folgt der Rotation, siehe -F statt -f)
            echo "alias tail-${aname}='tail -F /var/mqm/qmgrs/${qm}/errors/AMQERR01.LOG'"
            # Interaktive MQSC-Sitzung fuer diesen QM
            echo "alias mqsc-${aname}='su -s /bin/bash mqm -c \"runmqsc ${qm}\"'"
            # Kurzer Status dieses einen QM
            echo "alias status-${aname}='su -s /bin/bash mqm -c \"dspmq -m ${qm} -o status\"'"
            # Start/Stopp (kontrolliert, wartet auf sauberes Herunterfahren)
            echo "alias start-${aname}='su -s /bin/bash mqm -c \"strmqm ${qm}\"'"
            echo "alias stop-${aname}='su -s /bin/bash mqm -c \"endmqm -w ${qm}\"'"
            # Kanalstatus - haeufigste Diagnose bei Verbindungsproblemen
            echo "alias chstatus-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY CHSTATUS(*) ALL\\\" | runmqsc ${qm}\"'"
            # Queue-Fuellstaende (mit MAXDEPTH als Referenz, nicht nur nackte Zahl) -
            # haeufigste Diagnose bei Nachrichtenstau
            echo "alias qdepth-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY QUEUE(*) CURDEPTH MAXDEPTH TYPE(QLOCAL)\\\" | runmqsc ${qm}\"'"
            # Transmit-Queue-Fuellstaende: eigener, gezielter Blick auf Kanaele zu
            # anderen Queue Managern (Cluster/Punkt-zu-Punkt/MQTT-Transmit-Queue) -
            # ein wachsender XMITQ deutet meist auf einen gestoppten/haengenden
            # Sender-Kanal hin, geht in der normalen Queue-Liste sonst leicht unter
            echo "alias xmitq-${aname}='su -s /bin/bash mqm -c \"echo \\\"DISPLAY QUEUE(*) WHERE(USAGE EQ XMITQ) CURDEPTH MAXDEPTH\\\" | runmqsc ${qm}\"'"
        done <<< "$all_qms"
        # Globale (nicht QM-spezifische) Kurzbefehle
        echo "alias mqver='dspmqver'"
        echo "alias qmlist='su -s /bin/bash mqm -c \"dspmq -o status -o installation\"'"
    } > "$afile" 2>>"$LOGFILE" || { warn "Konnte '$afile' nicht schreiben - Aliase uebersprungen."; return 0; }
    chmod 644 "$afile" 2>/dev/null || true
    narrate "Aliase je QM (tail-/mqsc-/status-/start-/stop-/chstatus-/qdepth-/xmitq-<qm>) sowie global (mqver, qmlist)"
    narrate "angelegt in: $afile (wirksam nach neuer Anmeldung)"
}
setup_aliases

#-------------------------------------------------------------------------------
# 15b) MQ Web Console (mqweb) einrichten – Benutzer/Passwort/Rollen
#-------------------------------------------------------------------------------
configure_web_console() {
    [[ "$INST_WEB" == "yes" ]] || return 0
    info "Konfiguriere MQ Web Console (mqweb) ..."

    # Installationsnamen ermitteln (Default: Installation1)
    local instname webdir
    instname="$("$MQ_INSTALL_PATH/bin/dspmqinst" 2>/dev/null | awk -F': *' '/InstName/{print $2; exit}')" || true
    instname="${instname:-Installation1}"

    # mqweb-Serververzeichnis finden bzw. anlegen
    webdir="$(find /var/mqm/web/installations -maxdepth 3 -type d -name mqweb 2>/dev/null | head -n1)"
    if [[ -z "$webdir" ]]; then
        webdir="/var/mqm/web/installations/${instname}/servers/mqweb"
        mkdir -p "$webdir"
    fi
    info "mqweb-Konfigverzeichnis: $webdir"

    # Passwoerter mit securityUtility kodieren (hash bevorzugt, sonst xor)
    local secutil="$MQ_INSTALL_PATH/web/bin/securityUtility"
    encode_pw() {
        local plain="$1" enc=""
        if [[ -x "$secutil" ]]; then
            enc="$("$secutil" encode --encoding=hash "$plain" 2>/dev/null | grep -E '^\{' | tail -n1)"
            [[ -z "$enc" ]] && enc="$("$secutil" encode "$plain" 2>/dev/null | grep -E '^\{' | tail -n1)"
        fi
        if [[ -n "$enc" ]]; then echo "$enc"; else
            warn "securityUtility nicht verfuegbar – Passwort wird im Klartext gespeichert!"
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

    # Bestehende Konfiguration sichern
    [[ -f "$webdir/mqwebuser.xml" ]] && cp -a "$webdir/mqwebuser.xml" "$webdir/mqwebuser.xml.bak-$(date +%s)"

    # Neue mqwebuser.xml erzeugen (Basic Registry + Rollenzuordnung)
    cat > "$webdir/mqwebuser.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<server>
    <featureManager>
        <feature>appSecurity-2.0</feature>
        <feature>basicAuthenticationMQ-1.0</feature>
    </featureManager>

    <!-- Basic Registry: Benutzer existieren nur hier (kein OS-Konto noetig).
         Passwoerter sind mit securityUtility kodiert. -->
    <basicRegistry id="basic" realm="defaultRealm">
        <user name="$WEB_ADMIN_USER" password="$admin_pw_enc"/>
$ro_user_xml
        <group name="MQWebAdminGroup" realm="defaultRealm">
            <member name="$WEB_ADMIN_USER"/>
        </group>
    </basicRegistry>

    <!-- Rollen fuer die IBM MQ Console -->
    <enterpriseApplication id="com.ibm.mq.console">
        <application-bnd>
            <security-role name="MQWebAdmin">
                <group name="MQWebAdminGroup" realm="defaultRealm"/>
            </security-role>
$ro_role_console
        </application-bnd>
    </enterpriseApplication>

    <!-- Rollen fuer die administrative REST API -->
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
    info "mqwebuser.xml geschrieben (Rechte 600, Backup falls vorhanden)."

    # Host/Port konfigurieren
    if [[ "$WEB_REMOTE" == "yes" ]]; then
        "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpHost -v "*" >>"$LOGFILE" 2>&1 \
            || warn "setmqweb httpHost fehlgeschlagen."
        warn "Remote-Zugriff aktiviert (alle Interfaces) – unbedingt per Firewall einschraenken!"
    else
        "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpHost -v "localhost" >>"$LOGFILE" 2>&1 || true
    fi
    "$MQ_INSTALL_PATH/bin/setmqweb" properties -k httpsPort -v "$WEB_HTTPS_PORT" >>"$LOGFILE" 2>&1 \
        || warn "setmqweb httpsPort fehlgeschlagen."

    # mqweb-Server starten
    info "Starte mqweb-Server (kann einige Sekunden dauern) ..."
    "$MQ_INSTALL_PATH/bin/strmqweb" >>"$LOGFILE" 2>&1 \
        || warn "strmqweb meldete einen Fehler (laeuft der Server evtl. bereits?)."

    # Firewall fuer HTTPS-Port (nur bei Remote-Zugriff)
    if [[ "$WEB_REMOTE" == "yes" ]]; then
        if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
            firewall-cmd --permanent --add-port="${WEB_HTTPS_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            info "firewalld: Port $WEB_HTTPS_PORT/tcp freigegeben."
        elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
            ufw allow "${WEB_HTTPS_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            info "ufw: Port $WEB_HTTPS_PORT/tcp freigegeben."
        fi
    fi

    # Console-URL ermitteln
    WEB_URL="$("$MQ_INSTALL_PATH/bin/dspmqweb" 2>/dev/null | grep -oE 'https://[^ ]*console/' | head -n1)" || true
    [[ -z "$WEB_URL" ]] && WEB_URL="https://<host>:${WEB_HTTPS_PORT}/ibmmq/console/"
    narrate "MQ Web Console: $WEB_URL"
}
configure_web_console

#-------------------------------------------------------------------------------
# 16) Firewall-Hinweis / -Freigabe
#-------------------------------------------------------------------------------
configure_firewall() {
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        if [[ "$(ask_yes_no "Port $MQ_LISTENER_PORT/tcp in firewalld oeffnen?" 'yes')" == "yes" ]]; then
            firewall-cmd --permanent --add-port="${MQ_LISTENER_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            firewall-cmd --reload >>"$LOGFILE" 2>&1 || true
            info "firewalld: Port $MQ_LISTENER_PORT/tcp freigegeben."
        fi
    elif command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then
        if [[ "$(ask_yes_no "Port $MQ_LISTENER_PORT/tcp in ufw oeffnen?" 'yes')" == "yes" ]]; then
            ufw allow "${MQ_LISTENER_PORT}/tcp" >>"$LOGFILE" 2>&1 || true
            info "ufw: Port $MQ_LISTENER_PORT/tcp freigegeben."
        fi
    else
        warn "Keine aktive firewalld/ufw erkannt – Port $MQ_LISTENER_PORT/tcp ggf. manuell freigeben."
    fi
}
configure_firewall

#-------------------------------------------------------------------------------
# 17) systemd-Autostart (optional, IBM-empfohlenes Vorgehen)
#-------------------------------------------------------------------------------
setup_autostart() {
    [[ "$ENABLE_AUTOSTART" == "yes" ]] || return 0
    command -v systemctl >/dev/null 2>&1 || { warn "systemd nicht verfuegbar – Autostart uebersprungen."; return 0; }

    local qm unit
    for qm in "${QMGR_NAMES[@]}"; do
        info "Richte systemd-Service fuer QM '$qm' ein ..."
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
# PAM-Limits (limits.conf) gelten laut IBM-Doku NICHT fuer per systemd
# gestartete Queue Manager - daher hier explizit setzen.
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
            warn "Aktivieren von ibmmq-${qm}.service fehlgeschlagen."
        info "Autostart aktiviert: ibmmq-${qm}.service"
    done

    # mqweb-Server-Autostart (laeuft unabhaengig vom Queue Manager)
    if [[ "$INST_WEB" == "yes" ]]; then
        info "Richte systemd-Service fuer mqweb ein ..."
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
            warn "Aktivieren von ibmmq-web.service fehlgeschlagen."
        info "Autostart aktiviert: ibmmq-web.service"
    fi
}
setup_autostart

#-------------------------------------------------------------------------------
# 18) Verifikation
#-------------------------------------------------------------------------------
verify() {
    info "==== Verifikation ===="
    local qm
    for qm in "${QMGR_NAMES[@]}"; do
        su -s /bin/bash mqm -c "dspmq -m '$qm'" | tee -a "$LOGFILE" || true
        su -s /bin/bash mqm -c "echo 'DISPLAY LSSTATUS(*) STATUS' | runmqsc '$qm'" \
            2>/dev/null | grep -i status | tee -a "$LOGFILE" || true
    done
}
verify

#-------------------------------------------------------------------------------
# 19) Abschluss / Hinweise inkl. MQ-Explorer-Verbindungsparameter
#-------------------------------------------------------------------------------

# Host/IP fuer die Verbindung ermitteln
HOST_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo '<host>')"
HOST_IPS="$(hostname -I 2>/dev/null | tr -s ' ' | sed 's/ *$//')"
[[ -z "$HOST_IPS" ]] && HOST_IPS="<ip-adresse>"

cat <<EOF | tee -a "$LOGFILE"

================================================================================
 IBM MQ Installation abgeschlossen.
================================================================================
 Installierte MQ-Version : ${MQ_INSTALLED_VERSION:-unbekannt}
 Angelegte Queue Manager : ${#QMGR_NAMES[@]}
 App-Benutzer            : $MQ_APP_USER   (nicht privilegiert, MCAUSER der Kanaele)
 Berechtigungsgruppe     : $MQ_APP_GROUP  (setmqaut-Rechte liegen auf dieser Gruppe)
 Host (FQDN)             : $HOST_FQDN
 Host (IP-Adressen)      : $HOST_IPS
 Logfile                 : $LOGFILE

 PFLICHT-FOLGESCHRITT:
   Passwort fuer den App-Benutzer setzen (CONNAUTH prueft OS-User/Passwort):
       sudo passwd $MQ_APP_USER
EOF

# ---- MQ-Explorer-Verbindungsparameter pro Queue Manager ----

# Persistente Datei zum spaeteren Nachschlagen (nicht nur Terminal/Logfile)
EXPLORER_FILE="/var/mqm/mq-explorer-connections.txt"
if [[ -f "$EXPLORER_FILE" ]]; then
    # Datei existiert schon (z. B. aus einer frueheren Installation) - anhaengen
    # statt ueberschreiben, damit bei spaeterem "Weiteren QM hinzufuegen" die
    # Verbindungsdaten frueherer Queue Manager erhalten bleiben.
    {
        echo ""
        echo "################################################################################"
        echo "# Aktualisiert: $(date '+%F %T')  (neuer Lauf - vorherige Eintraege bleiben erhalten)"
        echo "################################################################################"
    } >> "$EXPLORER_FILE" 2>/dev/null || EXPLORER_FILE="$LOGFILE"
else
    : > "$EXPLORER_FILE" 2>/dev/null || EXPLORER_FILE="$LOGFILE"  # Fallback, falls nicht schreibbar
fi

cat <<EOF | tee -a "$LOGFILE" "$EXPLORER_FILE"

================================================================================
 MQ EXPLORER – VERBINDUNGSPARAMETER
 (Rechtsklick auf "Queue Managers" -> "Add Remote Queue Manager...")
 In diesem Lauf konfigurierte Queue Manager: ${#QMGR_NAMES[@]}
================================================================================
EOF
for _i in "${!QMGR_NAMES[@]}"; do
    _qm="${QMGR_NAMES[$_i]}"
    _port="${QMGR_PORTS[$_i]}"
    _chan="${QMGR_CHANNELS[$_i]}"
    {
        echo ""
        echo " Queue Manager #$(( _i + 1 )): $_qm"
        echo " ---------------------------------------------------------------"
        echo "   Queue manager name .......... : $_qm"
        echo "   Host name or IP address ..... : $HOST_FQDN   (oder: $HOST_IPS)"
        echo "   Port number ................. : $_port"
        echo ""
        echo "   >>> Verbindung ueber MQ EXPLORER / Admin-Tools <<<"
        echo "   Server-connection channel ... : $MQ_EXPLORER_CHANNEL"
        if [[ "$SEC_CONNAUTH" == "yes" ]]; then
            echo "     User ID .................... : $MQ_APP_USER  (+ dessen OS-Passwort)"
        fi
        echo ""
        echo "   Verbindung fuer ANWENDUNGEN:"
        echo "   Server-connection channel ... : $_chan"
        if [[ "$SEC_CONNAUTH" == "yes" ]]; then
            echo "   [x] Enable user identification"
            echo "       User ID ................. : $MQ_APP_USER"
            echo "       Password ................ : <OS-Passwort von $MQ_APP_USER>"
        else
            echo "   [ ] User identification ..... : (CONNAUTH deaktiviert)"
        fi
        if [[ "$SEC_TLS" == "yes" ]]; then
            echo "   [x] Enable SSL/TLS (gilt fuer beide Kanaele oben)"
            echo "       CipherSpec .............. : $TLS_CIPHER"
            echo "       QMGR-Zertifikat-Label ... : qm.${_qm,,}"
            echo "       Hinweis: Das QM-Zertifikat aus"
            echo "                /var/mqm/qmgrs/${_qm}/ssl/key.kdb"
            echo "                exportieren und in den Client-Truststore importieren."
        fi
    } | tee -a "$LOGFILE" "$EXPLORER_FILE"
done

# ---- Kompakte Tabellenuebersicht (schnelles Copy & Paste) ----
{
    echo ""
    echo " Kurzuebersicht:"
    printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" "QUEUE MANAGER" "HOST" "PORT" "KANAL (APP)" "KANAL (EXPLORER)" "TLS"
    printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" "---------------" "-------------------------" "------" "-----------------" "-----------------" "----------"
    for _i in "${!QMGR_NAMES[@]}"; do
        printf "   %-15s %-25s %-6s %-17s %-17s %-10s\n" \
            "${QMGR_NAMES[$_i]}" "$HOST_FQDN" "${QMGR_PORTS[$_i]}" "${QMGR_CHANNELS[$_i]}" "$MQ_EXPLORER_CHANNEL" \
            "$( [[ "$SEC_TLS" == "yes" ]] && echo "ja" || echo "nein" )"
    done
} | tee -a "$LOGFILE" "$EXPLORER_FILE"

# ---- Alle Queue Manager auf diesem Host (inkl. bereits vorhanden aus frueheren Laeufen) ----
if id mqm >/dev/null 2>&1; then
    _all_qm_raw="$(su -s /bin/bash mqm -c "dspmq -o status" 2>/dev/null || true)"
    if [[ -n "$_all_qm_raw" ]]; then
        {
            echo ""
            echo "================================================================================"
            echo " ALLE QUEUE MANAGER AUF DIESEM HOST"
            echo "================================================================================"
            while IFS= read -r _line; do
                [[ -z "$_line" ]] && continue
                _name="$(echo "$_line" | sed -n "s/.*QMNAME(\([^)]*\)).*/\1/p")"
                _known="nein"
                for _known_qm in "${QMGR_NAMES[@]}"; do
                    [[ "$_known_qm" == "$_name" ]] && _known="ja"
                done
                if [[ "$_known" == "ja" ]]; then
                    echo "   $_line   <- in diesem Lauf konfiguriert, siehe Details oben"
                else
                    echo "   $_line   <- bereits vorhanden, Port/Kanal ggf. mit 'runmqsc $_name' pruefen"
                fi
            done <<< "$_all_qm_raw"
        } | tee -a "$LOGFILE" "$EXPLORER_FILE"
    fi
fi

info "MQ-Explorer-Verbindungsdetails gespeichert unter: $EXPLORER_FILE"

cat <<EOF | tee -a "$LOGFILE"

 Hinweise zur MQ-Explorer-Verbindung:
   - MQ Explorer laeuft als separater Client; bei Remote-Verbindung muss der
     jeweilige Listener-Port in der Firewall erreichbar sein.
   - Da privilegierte Admins auf Kanaelen geblockt sind ($SEC_BLOCK_PRIV),
     mit dem nicht-privilegierten App-Benutzer verbinden (siehe oben).
   - Lokaler Zugriff (auf diesem Host, als mqm) ist auch direkt moeglich:
       sudo su - mqm -s /bin/bash -c "dspmq"
   - Vollstaendige Verbindungsdetails stehen jederzeit in: $EXPLORER_FILE
EOF

if [[ "$SEC_TLS" == "yes" ]]; then
cat <<EOF | tee -a "$LOGFILE"

 TLS-HINWEIS:
   Pro QM wurde ein Self-Signed-Zertifikat erzeugt (nur fuer Tests).
   Fuer Produktion durch ein CA-signiertes Zertifikat ersetzen und an die
   Clients verteilen. Client-seitig CipherSpec '$TLS_CIPHER' setzen.
EOF
fi

if [[ "$INST_WEB" == "yes" ]]; then
cat <<EOF | tee -a "$LOGFILE"

 WEB CONSOLE (verwaltet alle Queue Manager dieses Hosts):
     URL            : ${WEB_URL:-https://<host>:${WEB_HTTPS_PORT}/ibmmq/console/}
     Admin-Benutzer : $WEB_ADMIN_USER  (Rolle MQWebAdmin)$( [[ -n "$WEB_RO_USER" ]] && echo "
     Nur-Lese-User  : $WEB_RO_USER  (Rolle MQWebAdminRO)" )
     Remote-Zugriff : $WEB_REMOTE   (HTTPS-Port $WEB_HTTPS_PORT)
     Steuern        : strmqweb / endmqweb / dspmqweb  (Service: ibmmq-web.service)
     Hinweis: selbstsigniertes Zertifikat -> Browser-Warnung beim ersten Aufruf
              ist normal. Web-Benutzer existieren nur in der mqweb-Registry.
EOF
fi

if [[ "$ENABLE_ALIASES" == "yes" ]]; then
    _qm_suffixes=""
    for _qm in "${QMGR_NAMES[@]}"; do
        _aname="$(printf '%s' "${_qm,,}" | tr -c 'a-z0-9' '_')"
        _qm_suffixes+="${_qm_suffixes:+, }${_aname}"
    done
cat <<EOF | tee -a "$LOGFILE"

 BEQUEMLICHKEITS-ALIASE (systemweit, wirksam nach neuer Anmeldung):
     Je QM: tail-<qm> / mqsc-<qm> / status-<qm> / start-<qm> / stop-<qm> / chstatus-<qm> / qdepth-<qm> / xmitq-<qm>
     Verfuegbare QM-Suffixe: $_qm_suffixes
     Global: mqver, qmlist
     Beispiel: tail-${QMGR_NAMES[0],,} (folgt dem aktuellen Error-Log, auch bei Rotation)
     Vollstaendige Uebersicht: Hauptmenue -> 'Alias-Uebersicht anzeigen'
EOF
fi

cat <<EOF | tee -a "$LOGFILE"

 Best Practices, die dieses Script bereits angewandt hat:
   - Dedizierter, nicht privilegierter App-User (kein Mitglied von 'mqm')
   - CONNAUTH (CHCKCLNT REQUIRED) + CHLAUTH aktiv (je QM)
   - Privilegierte Admins auf Kanaelen geblockt
   - Eigener SVRCONN-Kanal mit festem MCAUSER statt SYSTEM.DEF.SVRCONN
   - Minimale Berechtigungen via setmqaut (Least Privilege)$( [[ "$INST_WEB" == "yes" ]] && echo "
   - Web Console: Basic Registry, kodierte Passwoerter, Rollentrennung" )
================================================================================
EOF

if [[ "$UI_MODE" == "tui" ]]; then
    read -r _rows _cols <<< "$(ui_dims)"
    "$UI_TOOL" --backtitle "$UI_BACKTITLE" --title "Installation abgeschlossen" \
        --msgbox "IBM MQ Installation abgeschlossen.\n\n${#QMGR_NAMES[@]} Queue Manager in diesem Lauf konfiguriert.\n\nMQ-Explorer-Verbindungsparameter stehen in:\n$EXPLORER_FILE\n\nVolles Logfile:\n$LOGFILE\n\nWichtig: Passwort fuer '$MQ_APP_USER' noch setzen (sudo passwd $MQ_APP_USER)." \
        "$_rows" "$_cols" 3>&1 1>&2 2>&3 || true
fi

info "Fertig."
exit 0
}

#-------------------------------------------------------------------------------
# 6) Aeussere Schleife: fuehrt run_main_flow() in einer Subshell aus. Ein
#    Benutzer-Abbruch (cancel_to_menu(), reservierter Exit-Code 99) laesst
#    die Subshell mit genau diesem Code enden - unabhaengig davon, wie tief
#    verschachtelt (ask()/ask_yes_no()/ask_secret(), beliebige perform_*-
#    Funktion) der Abbruch ausgeloest wurde. Die Schleife erkennt das und
#    zeigt einfach main_menu erneut, statt das Script zu beenden. Jeder
#    andere Exit-Code (0 = erfolgreich abgeschlossen, 1 = echter Fehler via
#    die()) beendet das Script wie bisher ueblich.
#-------------------------------------------------------------------------------
while true; do
    _flow_rc=0
    ( run_main_flow ) || _flow_rc=$?
    if [[ $_flow_rc -eq 99 ]]; then
        continue
    fi
    exit $_flow_rc
done
