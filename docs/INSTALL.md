# IBM MQ 9.4.x / 10.x – Installation Guide (Quick Start)

**English** | [Deutsch](INSTALL.de.md) · Script: `install-ibmmq.sh`

## 1. Prerequisites

- **Operating system:** RHEL/Rocky/Alma 8+, SUSE SLES 15+, Ubuntu 20.04+ / Debian 11+
  (x86_64 or ARM64; 32-bit ARM only "as-is" without IBM support)
- **Privileges:** root (or `sudo`)
- **Installation media:** IBM MQ installation package, e.g.
  - Developer Edition: `mqadv_dev941_linux_x86-64.tar.gz` (free of charge from IBM)
  - Licensed version: the matching `.tar.gz` from IBM Passport Advantage
  - Extracted OR as `.tar.gz` – the script finds `mqlicense.sh` by itself (up to 5 levels deep)
- **Optional:** `whiptail` for the dialog interface (otherwise text mode is used automatically)

## 2. Start the installation

```bash
# Make the script executable
chmod +x install-ibmmq.sh

# Start interactively (recommended the first time)
sudo ./install-ibmmq.sh
```

The main menu appears. For a new installation choose **item 1** and follow the dialogs. The
media path is asked for if it was not given via `--media`:

```bash
sudo ./install-ibmmq.sh --media /path/to/mqadv_dev941_linux_x86-64.tar.gz
```

In text mode (no whiptail, or `--no-tui`) the toggle menus use `c` to continue and `b` to go
back to the main menu.

## 3. What the new installation sets up

1. OS preparation (packages, kernel parameters, ulimits – only raised, never lowered)
2. IBM MQ packages (runtime, server, optionally AMS/Web Console)
3. Users/groups: `mqm` (service), app user (default `mqapp`, non-privileged),
   permission group (default `mqappusers`)
4. One or more queue managers with:
   - TCP listener (default port 1414, +1 per additional QM)
   - CONNAUTH (password required) + CHLAUTH (channel rules) following IBM best practice
   - Application channel (default `APP.SVRCONN`) with a fixed MCAUSER
   - **Dedicated MQ Explorer/admin channel** (default `EXPLORER.SVRCONN`)
   - Optional TLS (self-signed to start with, a real CA via the SSL/TLS management)
   - Sample queue (default `APP.QUEUE.1`)
5. Optional: systemd autostart, MQ Web Console, convenience aliases
6. Final summary with all MQ Explorer connection parameters
   (also stored persistently in `/var/mqm/mq-explorer-connections.txt`)

## 4. Mandatory next step

CONNAUTH checks the OS user and password – so set it once after the installation:

```bash
sudo passwd mqapp     # or the app user you chose
```

## 5. Test the connection with MQ Explorer

In MQ Explorer: right-click "Queue Managers" → "Add Remote Queue Manager…"

| Field | Value |
|---|---|
| Queue manager name | e.g. `QM1` |
| Host | server FQDN or IP |
| Port | e.g. `1414` |
| Server-connection channel | `EXPLORER.SVRCONN` |
| User ID + password | app user + its OS password |

All values are shown in the final summary and stored in
`/var/mqm/mq-explorer-connections.txt`.

## 6. Unattended run (no dialogs)

```bash
# One queue manager
sudo MQ_MODE=install MQ_QMGR_NAME=QM1 MQ_LISTENER_PORT=1414 \
     ./install-ibmmq.sh --media /path/to/media --non-interactive

# Several queue managers: NAME[:PORT[:CHANNEL]], comma-separated
sudo MQ_MODE=install MQ_QMGRS="QM1:1414,QM2:1415" \
     ./install-ibmmq.sh --media /path/to/media --non-interactive
```

All variables are documented at the top of the script (section "Global defaults").

## 7. Where do I find what?

| What | Where |
|---|---|
| Installation log | `/var/log/ibmmq-install-<timestamp>.log` |
| MQ Explorer connection data | `/var/mqm/mq-explorer-connections.txt` |
| Error log of a QM | `/var/mqm/qmgrs/<QM>/errors/AMQERR01.LOG` (or alias `tail-<qm>`) |
| Aliases | `/etc/profile.d/mqm-aliases.sh` (active after a new login) |
| Backups | `/var/mqm-backups/` (default) |

More details: see [DOCUMENTATION.md](DOCUMENTATION.md).
