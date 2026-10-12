# IBM MQ Installations-Script

[![ShellCheck](https://github.com/mradeka/IBM-MQ-Installation-Script/actions/workflows/shellcheck.yml/badge.svg)](https://github.com/mradeka/IBM-MQ-Installation-Script/actions/workflows/shellcheck.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE.md)
![IBM MQ](https://img.shields.io/badge/IBM%20MQ-9.4.x%20%7C%2010.0.x-052FAD)
![Platforms](https://img.shields.io/badge/platform-RHEL%20%7C%20SLES%20%7C%20Ubuntu%20%7C%20Debian%20%7C%20Raspberry%20Pi-lightgrey)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)

[English](README.md) | **Deutsch**

Interaktives Bash-Script zum Installieren, Absichern und Betreiben von **IBM MQ 9.4.x und 10.0.x**
unter Linux – vom ersten Paket über TLS-Zertifikate und Backups bis zur täglichen Fehlersuche.

```bash
sudo ./install-ibmmq.sh --media /pfad/zu/mqadv_dev941_linux_x86-64.tar.gz
```

## Highlights

- **Ein Script für den ganzen Lebenszyklus** – Neuinstallation, weitere Queue Manager,
  Backup/Restore, Upgrade (mit hartem Downgrade-Schutz), Zusatzfeatures (MQTT, AMS, Web Console),
  Deinstallation
- **IBM Security Best Practices ab Werk** – CONNAUTH, CHLAUTH, geblockte privilegierte Benutzer,
  dedizierte Kanäle mit festem, nicht-privilegiertem MCAUSER, Least Privilege über eine
  Berechtigungsgruppe
- **Eigener MQ-Explorer-Kanal** (`EXPLORER.SVRCONN`) neben dem Anwendungskanal
- **SSL/TLS-Verwaltung** – Self-Signed-Zertifikate, CSR für eine echte CA, Trust-Chain, Passwortwechsel
- **OS-Tuning nach IBM-Doku** – Kernel-Parameter und ulimits (nur anheben, nie absenken),
  zusätzlich `LimitNOFILE`/`LimitNPROC` in den systemd-Units
- **Troubleshooting-Aliase** – `tail-<qm>`, `chstatus-<qm>`, `qdepth-<qm>`, `xmitq-<qm>` u. a.
- **whiptail-TUI** mit automatischem Text-Modus-Fallback, **Automatisierungsmodus** für CI/CD
- Abbrechen/ESC führt immer zurück ins Hauptmenü – nur echte Fehler beenden das Script

## Unterstützte Plattformen

| Distribution | Paketformat |
|---|---|
| RHEL 8/9/10 und kompatible (Rocky, Alma) | RPM |
| SUSE Linux Enterprise Server 15 | RPM |
| Ubuntu 20.04/22.04/24.04, Debian | DEB |
| Raspberry Pi 4/5 mit 64-Bit-OS | DEB (ARM64) |
| Raspberry Pi mit 32-Bit-OS | DEB (ARM32, „as-is", ohne IBM-Support) |

Getestet auf Ubuntu 24.04 mit IBM MQ 9.4.1.0 Developer Edition.

## Dokumentation

- [Installationsanleitung](docs/INSTALL.de.md) – Schnellstart, erste Verbindung mit MQ Explorer
- [Vollständige Dokumentation](docs/DOCUMENTATION.de.md) – alle Menüpunkte, Sicherheitskonzept,
  TLS-Workflow, Backup/Restore, Aliase, Automatisierungsvariablen
- [Changelog](CHANGELOG.md) – Versionshistorie (Englisch)

Oberfläche und Meldungen des Scripts sind auf Englisch; die Dokumentation gibt es auf Englisch
und Deutsch.

## Voraussetzungen

- root bzw. `sudo`
- IBM-MQ-Installationsmedium (`.tar.gz` oder entpacktes Verzeichnis) – das Script lädt es
  **nicht** herunter (Lizenz-/Entitlement-Gründe). Die Developer Edition gibt es kostenlos bei IBM.

## Lizenz

GNU General Public License v2 – siehe [LICENSE.md](LICENSE.md). Ohne Gewähr.
