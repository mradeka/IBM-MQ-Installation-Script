# IBM MQ 9.4.x / 10.x – Installationsanleitung (Schnellstart)

Stand: 2026-07-31 · Script: `install-ibmmq-9.4.sh`

## 1. Voraussetzungen

- **Betriebssystem:** RHEL/Rocky/Alma 8+, SUSE SLES 15+, Ubuntu 20.04+ / Debian 11+
  (x86_64 oder ARM64; 32-Bit-ARM nur „as-is" ohne IBM-Support)
- **Rechte:** root (bzw. `sudo`)
- **Installationsmedium:** IBM-MQ-Installationspaket, z. B.
  - Developer Edition: `mqadv_dev941_linux_x86-64.tar.gz` (kostenlos von IBM)
  - Lizenzierte Version: entsprechendes `.tar.gz` von IBM Passport Advantage
  - Entpackt ODER als `.tar.gz` – das Script findet `mqlicense.sh` selbst (bis 5 Ebenen tief)
- **Optional:** `whiptail` für die Dialog-Oberfläche (sonst automatisch Text-Modus)

## 2. Installation starten

```bash
# Script ausführbar machen
chmod +x install-ibmmq-9.4.sh

# Interaktiv starten (empfohlen beim ersten Mal)
sudo ./install-ibmmq-9.4.sh
```

Das Hauptmenü erscheint. Für eine Neuinstallation: **Punkt 1** wählen und den
Dialogen folgen. Das Medium wird abgefragt, falls nicht per `--media` angegeben:

```bash
sudo ./install-ibmmq-9.4.sh --media /pfad/zu/mqadv_dev941_linux_x86-64.tar.gz
```

## 3. Was die Neuinstallation einrichtet

1. Betriebssystem-Vorbereitung (Pakete, Kernel-Parameter, ulimits – nur anheben, nie absenken)
2. IBM-MQ-Pakete (Runtime, Server, optional AMS/Web Console/MQTT)
3. Benutzer/Gruppen: `mqm` (Service), App-Benutzer (Standard `mqapp`, nicht privilegiert),
   Berechtigungsgruppe (Standard `mqappusers`)
4. Ein oder mehrere Queue Manager mit:
   - TCP-Listener (Standard-Port 1414, je QM +1)
   - CONNAUTH (Passwortpflicht) + CHLAUTH (Kanalregeln) nach IBM Best Practice
   - Anwendungs-Kanal (Standard `APP.SVRCONN`) mit festem MCAUSER
   - **Dediziertem MQ-Explorer-/Admin-Kanal** (Standard `EXPLORER.SVRCONN`)
   - Optional TLS (Self-Signed als Einstieg, echte CA über die TLS-Verwaltung)
   - Beispiel-Queue (Standard `APP.QUEUE.1`)
5. Optional: systemd-Autostart, MQ Web Console, Bequemlichkeits-Aliase
6. Abschluss-Zusammenfassung mit allen MQ-Explorer-Verbindungsparametern
   (auch persistent in `/var/mqm/mq-explorer-connections.txt`)

## 4. Pflicht-Folgeschritt

CONNAUTH prüft OS-Benutzer/Passwort – daher nach der Installation einmalig:

```bash
sudo passwd mqapp     # bzw. der gewählte App-Benutzer
```

## 5. Verbindung mit MQ Explorer testen

Im MQ Explorer: Rechtsklick auf „Queue Managers" → „Add Remote Queue Manager…"

| Feld | Wert |
|---|---|
| Queue manager name | z. B. `QM1` |
| Host | Server-FQDN oder IP |
| Port | z. B. `1414` |
| Server-connection channel | `EXPLORER.SVRCONN` |
| User ID + Passwort | App-Benutzer + dessen OS-Passwort |

Alle Werte stehen in der Abschluss-Zusammenfassung und in
`/var/mqm/mq-explorer-connections.txt`.

## 6. Automatisierter Aufruf (ohne Dialoge)

```bash
sudo MQ_MODE=install MQ_QMGR_COUNT=1 MQ_QMGR_NAME=QM1 \
     ./install-ibmmq-9.4.sh --media /pfad/zum/medium --non-interactive
```

Alle Variablen sind im Script-Kopf dokumentiert (Abschnitt „Standardwerte").

## 7. Wo finde ich was?

| Was | Wo |
|---|---|
| Installations-Log | `/var/log/ibmmq-install-<zeitstempel>.log` |
| MQ-Explorer-Verbindungsdaten | `/var/mqm/mq-explorer-connections.txt` |
| Fehler-Log eines QM | `/var/mqm/qmgrs/<QM>/errors/AMQERR01.LOG` (oder Alias `tail-<qm>`) |
| Aliase | `/etc/profile.d/mqm-aliases.sh` (nach neuer Anmeldung aktiv) |
| Backups | `/var/mqm-backups/` (Standard) |

Weitere Details: siehe `DOKUMENTATION.md`.
