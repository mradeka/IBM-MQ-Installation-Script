# IBM MQ Installation Script

**English** | [Deutsch](README.de.md)

Interactive Bash script to install, harden and operate **IBM MQ 9.4.x and 10.0.x** on Linux –
from the first package to TLS certificates, backups and day-to-day troubleshooting.

```bash
sudo ./install-ibmmq.sh --media /path/to/mqadv_dev941_linux_x86-64.tar.gz
```

## Highlights

- **One script, all lifecycle tasks** – new installation, additional queue managers, backup/restore,
  upgrade (with hard downgrade protection), add-on features (MQTT, AMS, Web Console), uninstall
- **IBM security best practices out of the box** – CONNAUTH, CHLAUTH, blocked privileged users,
  dedicated channels with a fixed non-privileged MCAUSER, least privilege via a permission group
- **Separate MQ Explorer channel** (`EXPLORER.SVRCONN`) next to the application channel
- **SSL/TLS management** – self-signed certificates, CSR for a real CA, trust chain, password change
- **OS tuning per IBM docs** – kernel parameters and ulimits (only raised, never lowered),
  plus `LimitNOFILE`/`LimitNPROC` in the systemd units
- **Troubleshooting aliases** – `tail-<qm>`, `chstatus-<qm>`, `qdepth-<qm>`, `xmitq-<qm>` and more
- **whiptail TUI** with automatic text-mode fallback, **non-interactive mode** for CI/CD
- Cancel/ESC always returns to the main menu – only real errors end the script

## Supported platforms

| Distribution | Package format |
|---|---|
| RHEL 8/9/10 and compatibles (Rocky, Alma) | RPM |
| SUSE Linux Enterprise Server 15 | RPM |
| Ubuntu 20.04/22.04/24.04, Debian | DEB |
| Raspberry Pi 4/5 with 64-bit OS | DEB (ARM64) |
| Raspberry Pi with 32-bit OS | DEB (ARM32, "as-is", no IBM support) |

Tested on Ubuntu 24.04 with IBM MQ 9.4.1.0 Developer Edition.

## Documentation

- [Installation guide](docs/INSTALL.md) – quick start, first connection with MQ Explorer
- [Full documentation](docs/DOCUMENTATION.md) – all menu items, security concept, TLS workflow,
  backup/restore, aliases, automation variables

The script's user interface and messages are in English; the documentation is available in
English and German.

## Requirements

- root or `sudo`
- IBM MQ installation media (`.tar.gz` or extracted directory) – the script does **not** download
  it (license/entitlement reasons). The Developer Edition is available free of charge from IBM.

## License

GNU General Public License v2 – see [LICENSE.md](LICENSE.md). No warranty.
