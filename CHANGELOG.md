# Changelog

## 0.1.0

First release.

- Scan with a 0 to 100 score, plan (dry run), apply, undo, confirm, history, verify
- Every change is journaled and can be undone; failed runs undo themselves
- Rollback timer built on systemd, so it works even when your SSH session dies
- Modules: dns, bbr, sysctl, ssh, firewall, fail2ban, abuse, ipv6, mss, updates, timesync, journald, swap
- Profiles: recommended, vpn, web, bot, game, all
- Persian and English interface, interactive menu
- Optional check from Iranian probes and optional report to a PrivateChecker bot
