# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] – 2026-10-12

First versioned release. The script installs IBM MQ 9.4.x and 10.0.x; the version that is
installed is determined by the supplied installation media.

### Added
- Main menu with 11 actions: new installation, additional queue managers, backup, restore,
  upgrade, add-on features (MQTT/Telemetry, AMS), uninstall, object creation, SSL/TLS
  management, status with start/stop, alias overview
- Security defaults following IBM best practices: CONNAUTH, CHLAUTH, blocked privileged users,
  dedicated application channel and a separate MQ Explorer channel (`EXPLORER.SVRCONN`),
  each with a fixed non-privileged MCAUSER
- Least privilege via a permission group (`setmqaut` on the group instead of individual users)
- SSL/TLS management: self-signed certificates, CSR for a real CA, trust certificates,
  receiving signed certificates, listing/details, key repository password change
- OS tuning per IBM documentation: kernel parameters and ulimits (only raised, never lowered),
  `LimitNOFILE`/`LimitNPROC` in the systemd units
- Troubleshooting aliases per queue manager (`tail-`, `mqsc-`, `status-`, `start-`, `stop-`,
  `chstatus-`, `qdepth-`, `xmitq-<qm>`) plus `mqver` and `qmlist`
- Upgrade with a hard block on real downgrades before anything is changed
- MQ Explorer connection parameters in the final summary and in
  `/var/mqm/mq-explorer-connections.txt`
- whiptail TUI with automatic text-mode fallback; non-interactive mode for automation
- Cancel/ESC returns to the main menu at any point
- Bilingual documentation (English/German): README, installation guide, full documentation
- ShellCheck workflow (GitHub Actions)

### Changed
- Script renamed from `install-ibmmq-9.4.sh` to `install-ibmmq.sh`
- All script messages, dialogs and comments are now in English
- Text-mode toggle menus use `c` (continue) and `b` (back); the previous keys `f` and `z`
  are still accepted

### Fixed
- Code cleaned up for all ShellCheck warnings (behavior unchanged)

[1.0.0]: https://github.com/mradeka/IBM-MQ-Installation-Script/releases/tag/v1.0.0
