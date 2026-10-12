# IBM MQ 9.4.x / 10.x Installation & Management Script – Documentation

**English** | [Deutsch](DOCUMENTATION.de.md) · Script: `install-ibmmq.sh`

Tested with IBM MQ 9.4.1.0 Developer Edition on Ubuntu 24.04.

---

## 1. Overview

Interactive Bash script for installing and operating IBM MQ on Linux (RPM- and DEB-based
distributions, x86_64 and ARM64). All functions are available through a main menu (whiptail
dialogs or text mode) and through environment variables for automation.

### Main menu

| No. | Menu item | After completion |
|---|---|---|
| 1 | New installation (install packages + set up queue managers) | Script ends with summary |
| 2 | Add another queue manager to an existing installation | Script ends with summary |
| 3 | Back up one or all queue managers | back to the main menu |
| 4 | Restore a queue manager from a backup | back to the main menu |
| 5 | Upgrade an existing installation to a newer version | Script ends |
| 6 | Install an add-on feature (MQTT/Telemetry, AMS) | Script ends |
| 7 | Completely remove the IBM MQ installation (uninstall) | Script ends |
| 8 | Create objects for a queue manager (channels, listeners) | back to the main menu |
| 9 | SSL/TLS management (certificates, trust chain) | back to the main menu |
| 10 | Show status of existing queue managers (+ start/stop) | back to the main menu |
| 11 | Show alias overview | back to the main menu |
| 12 | Exit | – |

**Cancel/ESC returns to the main menu at any point** – only real errors end the script
(with an error message and a pointer to the logfile). In text mode the toggle menus use `c`
(continue) and `b` (back to the main menu).

---

## 2. Security concept (IBM best practices)

Every queue manager the script creates automatically gets:

- **CONNAUTH** (`CHCKCLNT(REQUIRED)`): client connections require an OS user + password.
  → Mandatory next step: `sudo passwd <app-user>`
- **CHLAUTH enabled** with block rules: privileged users (`*MQADMIN`) are blocked on all
  channels, `SYSTEM.DEF.SVRCONN` / `SYSTEM.ADMIN.SVRCONN` are locked.
- **Dedicated channels instead of SYSTEM channels:**
  - `APP.SVRCONN` – for applications
  - `EXPLORER.SVRCONN` – **only** for MQ Explorer / admin tools (separate, so that rules or
    lock-downs can be applied independently of applications)
  - Both with a fixed, non-privileged `MCAUSER`
- **Least privilege via a group:** permissions (`setmqaut`) are granted to the group
  (`mqappusers`), not to individual users. Simply add new app users/MCAUSERs to the group –
  no further `setmqaut` needed.
- **The app user is NOT a member of `mqm`** (otherwise it would be privileged).
- **Dead letter queue** is set (`SYSTEM.DEAD.LETTER.QUEUE`).
- **MAXCHL/MAXACTCHL** are written correctly to `qm.ini` (stanza `Channels:`), not to MQSC
  (they are not valid `ALTER QMGR` parameters).

---

## 3. OS tuning

Optional during a new installation (default: yes):

- **Kernel parameters** according to the IBM docs ("Configuring the operating system on
  Linux") in `/etc/sysctl.d/99-ibmmq.conf`:
  `kernel.shmmni/shmall/shmmax`, `kernel.sem`, `fs.file-max`,
  `kernel.pid_max` (IBM: 120000), `kernel.threads-max`
  – **values are only raised, never lowered below a better existing value**
  (each of the 4 `kernel.sem` values is checked individually).
- **ulimits** for `mqm`/`root` in `/etc/security/limits.d/99-ibmmq.conf`
  (nofile 10240, nproc 4096).
- **systemd units** additionally get `LimitNOFILE`/`LimitNPROC`, because according to the IBM
  docs PAM limits do NOT apply to systemd services.

---

## 4. SSL/TLS management (menu item 9)

Per queue manager, key repository at `/var/mqm/qmgrs/<QM>/ssl/key.kdb` (CMS, with stash file;
password either generated automatically or chosen by you):

| Action | Purpose |
|---|---|
| Create/renew a self-signed certificate | Quick start/test; sets SSLKEYR/CERTLABL + REFRESH SECURITY |
| Create a CSR for a real CA | Production path: certificate request for a real CA (`runmqakm -certreq -create`) |
| Add a CA root/intermediate certificate | CA root/intermediate certificate (`-cert -add`) – **BEFORE** importing! |
| Import the certificate signed by the CA | `-cert -receive` (links it with the private key; `-add` would be wrong!) |
| Show the certificates | `-cert -list` |
| Show details/expiry date | `-cert -details` |
| Change the password | `-keydb -changepw` (current password required) |

**Order of the CA workflow:** create CSR → send it to the CA → import the root/intermediate
certificates as trusted → **only then** receive the signed certificate (otherwise the trust
chain check fails).

---

## 5. Create objects (menu item 8)

For an existing QM, via checklist:

- **SVRCONN channel** following best practice: dedicated name, fixed non-privileged MCAUSER,
  CHLAUTH ADDRESSMAP, optional TLS. The MCAUSER is added to the permission group automatically.
- **TCP listener**: own name/port, `CONTROL(QMGR)`, gets started; optionally opens the
  firewall (firewalld/ufw).
- The result shows ready-to-use MQ Explorer connection parameters.

---

## 6. Backup & restore (menu items 3/4)

**Backup** (`/var/mqm-backups/`, timestamp in the file name):
- Configuration: `dmpmqcfg -m <QM> -x all -a` → `<QM>-config-<ts>.mqsc`
- Data/logs: tar archive → `<QM>-data-<ts>.tar.gz` (the QM is stopped briefly for this, if
  you choose so – recommended for a consistent archive)

**Restore:**
- `config` mode: replay the MQSC onto an existing/new QM (safe, possible while it is running)
- `full` mode: restore the data archive – the script stops the target QM itself, replaces its
  data and starts it again (overwrites data, asks for explicit confirmation)

---

## 7. Convenience aliases

System-wide in `/etc/profile.d/mqm-aliases.sh` (effective after a new login; deliberately NOT
in the `.profile` of the `mqm` user – it is a `nologin` service account whose `.profile` would
never be loaded). Regenerated on every run from **all** QMs present on the host.

| Alias (per QM) | Command |
|---|---|
| `tail-<qm>` | `tail -F .../errors/AMQERR01.LOG` (follows the log rotation!) |
| `mqsc-<qm>` | interactive `runmqsc` as `mqm` |
| `status-<qm>` | `dspmq -m <QM> -o status` |
| `start-<qm>` / `stop-<qm>` | `strmqm` / `endmqm -w` |
| `chstatus-<qm>` | `DISPLAY CHSTATUS(*) ALL` – channel status |
| `qdepth-<qm>` | `DISPLAY QUEUE(*) CURDEPTH MAXDEPTH TYPE(QLOCAL)` |
| `xmitq-<qm>` | transmission queue depths (`WHERE(USAGE EQ XMITQ)`) |

Global: `mqver` (dspmqver), `qmlist` (all QMs with status + installation).
QM names with `.`/`-` become `_` in the alias name (e.g. `PAY.QM` → `tail-pay_qm`).

---

## 8. Upgrade, add-on features, uninstall (menu items 5/6/7)

- **Upgrade:** version check BEFORE any change – real downgrades are blocked hard (the IBM
  packages refuse them internally and would otherwise leave a half-broken system). Optional
  backup of `/var/mqm` first. QMs are stopped, packages upgraded, QMs restarted.
- **Add-on feature:** MQTT/Telemetry (incl. the IBM sample MQSC for the MQXR service) and AMS
  can be installed later. The Web Console can only be selected during a new installation.
- **Uninstall:** stops the Web Console + all QMs, removes packages, systemd units, aliases,
  optionally the `mqm` user + `/var/mqm`. IRREVERSIBLE – a backup is offered first.

---

## 9. Automation

`--non-interactive` + environment variables (all documented at the top of the script):

```bash
sudo MQ_MODE=backup BACKUP_QMS=all ./install-ibmmq.sh --non-interactive
sudo MQ_MODE=install MQ_QMGRS="QM1:1414,QM2:1415" ./install-ibmmq.sh \
     --media /path/to/media --non-interactive
```

Important variables (excerpt): `MQ_MODE`, `MQ_QMGR_NAME`, `MQ_QMGRS`, `MQ_LISTENER_PORT`,
`MQ_APP_USER/GROUP/CHANNEL/QUEUE`, `MQ_EXPLORER_CHANNEL`,
`SEC_TLS/SEC_CONNAUTH/SEC_CHLAUTH/SEC_BLOCK_PRIV`, `INST_WEB`, `ENABLE_AUTOSTART`,
`ENABLE_ALIASES`, `OS_TUNE_MQ`, `BACKUP_DIR`, `RESTORE_*`, `UNINSTALL_*`.

In automation mode every action ends with exit code 0 (success) or 1 (error) – there is no
return to the menu.

---

## 10. Error handling & logging

- Complete log: `/var/log/ibmmq-install-<timestamp>.log`
- Errors show the line number + logfile path; the script aborts on real errors instead of
  silently continuing (`set -Eeuo pipefail`).
- `runmqsc` syntax errors during provisioning count as a total failure (deliberately: better
  to fail loudly than to leave a half-applied security configuration).
- The QM start detects AMQ7204E ("associated with a different installation") and tries a
  `setmqm` re-association automatically.

## 11. Known limitations

- MQ Appliance, z/OS, Windows: not supported (Linux only).
- ARM32 (32-bit Raspberry Pi): only "as-is", IBM offers no support.
- The TLS "change password" action requires the current password – an automatically generated
  (never displayed) password cannot be changed; in that case create the repository anew.
- Aliases/environment (`/etc/profile.d/`) only take effect after a new login.
