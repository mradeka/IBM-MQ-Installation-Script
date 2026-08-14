# IBM MQ Installation Script

Stand: 2026-07-31 · Script: `install-ibmmq-9.4.sh`
Getestet mit IBM MQ 9.4.1.0 Developer Edition auf Ubuntu 24.04.

---

## 1. Überblick

Interaktives Bash-Script zur Installation und laufenden Verwaltung von IBM MQ
auf Linux (RPM- und DEB-basierte Distributionen, x86_64 und ARM64). Alle
Funktionen sind über ein Hauptmenü (whiptail-Dialoge oder Text-Modus) sowie
über Umgebungsvariablen für die Automatisierung erreichbar.

### Hauptmenü

| Nr. | Aktion | Nach Abschluss |
|---|---|---|
| 1 | Neuinstallation (Pakete + Queue Manager) | Script endet mit Zusammenfassung |
| 2 | Weiteren Queue Manager hinzufügen | Script endet mit Zusammenfassung |
| 3 | Backup eines/aller Queue Manager | zurück ins Hauptmenü |
| 4 | Queue Manager aus Backup wiederherstellen | zurück ins Hauptmenü |
| 5 | Installation upgraden | Script endet |
| 6 | Zusatzfeature nachinstallieren (MQTT/AMS/Web) | Script endet |
| 7 | Installation vollständig entfernen | Script endet |
| 8 | Objekte erstellen (Kanäle, Listener) | zurück ins Hauptmenü |
| 9 | SSL/TLS-Verwaltung | zurück ins Hauptmenü |
| 10 | Status anzeigen (+ Start/Stopp) | zurück ins Hauptmenü |
| 11 | Alias-Übersicht anzeigen | zurück ins Hauptmenü |
| 12 | Beenden | – |

**Abbrechen (Cancel/ESC) führt an jeder Stelle zurück ins Hauptmenü** – nur
echte Fehler beenden das Script (mit Fehlermeldung und Logfile-Verweis).

---

## 2. Sicherheitskonzept (IBM Best Practices)

Das Script setzt bei jeder QM-Anlage automatisch um:

- **CONNAUTH** (`CHCKCLNT(REQUIRED)`): Client-Verbindungen brauchen
  OS-Benutzer + Passwort. → Pflicht-Folgeschritt: `sudo passwd <app-user>`
- **CHLAUTH aktiv** mit Block-Regeln: privilegierte Benutzer (`*MQADMIN`)
  werden auf allen Kanälen geblockt, `SYSTEM.DEF.SVRCONN` /
  `SYSTEM.ADMIN.SVRCONN` sind gesperrt.
- **Dedizierte Kanäle statt SYSTEM-Kanäle:**
  - `APP.SVRCONN` – für Anwendungen
  - `EXPLORER.SVRCONN` – **nur** für MQ Explorer / Admin-Tools (getrennt,
    damit Regeln/Sperrungen unabhängig von Anwendungen möglich sind)
  - Beide mit festem, nicht-privilegiertem `MCAUSER`
- **Least Privilege über eine Gruppe:** Berechtigungen (`setmqaut`) werden auf
  die Gruppe (`mqappusers`) vergeben, nicht auf Einzelbenutzer. Neue
  App-Benutzer/MCAUSER einfach in die Gruppe aufnehmen – kein erneutes
  `setmqaut` nötig.
- **App-Benutzer ist NICHT Mitglied von `mqm`** (sonst wäre er privilegiert).
- **Dead Letter Queue** wird gesetzt (`SYSTEM.DEAD.LETTER.QUEUE`).
- **MAXCHL/MAXACTCHL** landen korrekt in der `qm.ini` (Stanza `Channels:`),
  nicht im MQSC (dort sind sie keine gültigen `ALTER QMGR`-Parameter).

---

## 3. OS-Tuning

Bei der Neuinstallation optional (Standard: ja):

- **Kernel-Parameter** nach IBM-Doku („Configuring the operating system on
  Linux") in `/etc/sysctl.d/99-ibmmq.conf`:
  `kernel.shmmni/shmall/shmmax`, `kernel.sem`, `fs.file-max`,
  `kernel.pid_max` (IBM: 120000), `kernel.threads-max`
  – **Werte werden nur angehoben, nie unter einen besseren Bestand abgesenkt**
  (jeder der 4 `kernel.sem`-Teilwerte einzeln geprüft).
- **ulimits** für `mqm`/`root` in `/etc/security/limits.d/99-ibmmq.conf`
  (nofile 10240, nproc 4096).
- **systemd-Units** erhalten zusätzlich `LimitNOFILE`/`LimitNPROC`, da
  PAM-Limits für systemd-Dienste laut IBM-Doku NICHT greifen.

---

## 4. SSL/TLS-Verwaltung (Menüpunkt 9)

Pro Queue Manager, Key-Repository unter `/var/mqm/qmgrs/<QM>/ssl/key.kdb`
(CMS, mit Stash-Datei; Passwort wahlweise automatisch generiert oder selbst
vergeben):

| Aktion | Zweck |
|---|---|
| Self-Signed erstellen/erneuern | Schnelleinstieg/Test; setzt SSLKEYR/CERTLABL + REFRESH SECURITY |
| CSR erstellen | Produktionsweg: Zertifikatsanfrage für echte CA (`runmqakm -certreq -create`) |
| Trust-Zertifikat hinzufügen | Root-/Zwischenzertifikat der CA (`-cert -add`) – **VOR** dem Einspielen! |
| Signiertes Zertifikat einspielen | `-cert -receive` (verknüpft mit privatem Schlüssel; `-add` wäre falsch!) |
| Zertifikate anzeigen | `-cert -list` |
| Details/Ablaufdatum | `-cert -details` |
| Passwort ändern | `-keydb -changepw` (aktuelles Passwort erforderlich) |

**Reihenfolge beim CA-Workflow:** CSR erstellen → an CA senden →
Root-/Zwischenzertifikate als Trust einspielen → **erst dann** das signierte
Zertifikat empfangen (sonst schlägt die Trust-Chain-Prüfung fehl).

---

## 5. Objekte erstellen (Menüpunkt 8)

Für einen bestehenden QM per Checkliste:

- **SVRCONN-Kanal** nach Best Practice: dedizierter Name, fester
  nicht-privilegierter MCAUSER, CHLAUTH-ADDRESSMAP, optional TLS.
  Der MCAUSER wird automatisch der Berechtigungsgruppe hinzugefügt.
- **TCP-Listener**: eigener Name/Port, `CONTROL(QMGR)`, wird gestartet;
  optional Firewall-Freigabe (firewalld/ufw).
- Abschluss zeigt fertige MQ-Explorer-Verbindungsparameter.

---

## 6. Backup & Restore (Menüpunkte 3/4)

**Backup** (`/var/mqm-backups/`, Zeitstempel im Dateinamen):
- Konfiguration: `dmpmqcfg -m <QM> -x all -a` → `<QM>-config-<ts>.mqsc`
- Daten/Logs: tar-Archiv → `<QM>-data-<ts>.tar.gz` (QM wird dafür kurz
  gestoppt, auf Wunsch)

**Restore:**
- `config`-Modus: MQSC auf bestehenden/neuen QM zurückspielen
- `full`-Modus: Daten-Archiv entpacken (Ziel-QM muss gestoppt sein)

---

## 7. Bequemlichkeits-Aliase

Systemweit in `/etc/profile.d/mqm-aliases.sh` (wirksam nach neuer Anmeldung;
bewusst NICHT im `.profile` des `mqm`-Users – der ist ein `nologin`-
Service-Account, dessen `.profile` nie geladen würde). Wird bei jedem Lauf aus
**allen** auf dem Host vorhandenen QMs neu generiert.

| Alias (je QM) | Befehl |
|---|---|
| `tail-<qm>` | `tail -F .../errors/AMQERR01.LOG` (folgt der Log-Rotation!) |
| `mqsc-<qm>` | interaktives `runmqsc` als `mqm` |
| `status-<qm>` | `dspmq -m <QM> -o status` |
| `start-<qm>` / `stop-<qm>` | `strmqm` / `endmqm -w` |
| `chstatus-<qm>` | `DISPLAY CHSTATUS(*) ALL` – Kanalstatus |
| `qdepth-<qm>` | `DISPLAY QUEUE(*) CURDEPTH MAXDEPTH TYPE(QLOCAL)` |
| `xmitq-<qm>` | Transmit-Queue-Füllstände (`WHERE(USAGE EQ XMITQ)`) |

Global: `mqver` (dspmqver), `qmlist` (alle QMs mit Status + Installation).
QM-Namen mit `.`/`-` werden im Aliasnamen zu `_` (z. B. `PAY.QM` → `tail-pay_qm`).

---

## 8. Upgrade, Feature, Deinstallation (Menüpunkte 5/6/7)

- **Upgrade:** Versionsprüfung VOR jeder Änderung – echte Downgrades werden
  hart geblockt (IBM-Pakete verweigern sie intern und hinterlassen sonst ein
  halb zerstörtes System). Optional Backup vorab. QMs werden gestoppt,
  Pakete aktualisiert, QMs neu gestartet.
- **Feature:** MQTT/Telemetry (inkl. IBM-Sample-MQSC für den MQXR-Service),
  AMS, Web Console nachinstallierbar.
- **Deinstallation:** Stoppt Web Console + alle QMs, entfernt Pakete,
  systemd-Units, Aliase, optional `mqm`-User + `/var/mqm`.
  UNWIDERRUFLICH – vorher Backup empfohlen (wird angeboten).

---

## 9. Automatisierung

`--non-interactive` + Umgebungsvariablen (alle im Script-Kopf dokumentiert):

```bash
sudo MQ_MODE=backup BACKUP_QMS=all ./install-ibmmq-9.4.sh --non-interactive
sudo MQ_MODE=install MQ_QMGR_COUNT=2 ./install-ibmmq-9.4.sh \
     --media /pfad/medium --non-interactive
```

Wichtige Variablen (Auszug): `MQ_MODE`, `MQ_QMGR_NAME/COUNT`,
`MQ_LISTENER_PORT`, `MQ_APP_USER/GROUP/CHANNEL/QUEUE`, `MQ_EXPLORER_CHANNEL`,
`SEC_TLS/SEC_CONNAUTH/SEC_CHLAUTH`, `INST_WEB`, `ENABLE_AUTOSTART`,
`ENABLE_ALIASES`, `OS_TUNE_MQ`, `BACKUP_DIR`, `UNINSTALL_*`.

Im Automatisierungsmodus enden alle Aktionen mit Exit-Code 0 (Erfolg) bzw. 1
(Fehler) – kein Menü-Rücksprung.

---

## 10. Fehlerbehandlung & Logging

- Vollständiges Log: `/var/log/ibmmq-install-<zeitstempel>.log`
- Fehler zeigen Zeilennummer + Logfile-Pfad; das Script bricht bei echten
  Fehlern ab, statt still weiterzumachen (`set -Eeuo pipefail`).
- `runmqsc`-Syntaxfehler in der Provisionierung gelten als Gesamt-Fehlschlag
  (bewusst: lieber laut scheitern als eine halbe Security-Konfiguration).
- QM-Start erkennt AMQ7204E („anderer Installation zugeordnet") und versucht
  automatisch `setmqm`-Neuzuordnung.

## 11. Bekannte Grenzen

- MQ Appliance, z/OS, Windows: nicht unterstützt (Linux-only).
- ARM32 (32-Bit Raspberry Pi): nur „as-is", IBM bietet keinen Support.
- Der TLS-„Passwort ändern"-Punkt benötigt das aktuelle Passwort – ein
  automatisch generiertes (nie angezeigtes) Passwort kann nicht geändert
  werden; in dem Fall Repository neu anlegen.
- Aliase/Umgebung (`/etc/profile.d/`) wirken erst nach neuer Anmeldung.
