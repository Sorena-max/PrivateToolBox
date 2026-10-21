# Changelog

## 0.1.0

First release.

- Interactive menu: scan, six ready-made profiles, choose modules yourself, DNS test, verify, history, undo.
  The installer offers to open it right away
- Scan with a 0 to 100 score, plan (dry run), apply, undo, confirm, history, verify
- Every change is journaled and can be undone; failed runs undo themselves
- Rollback timer built on systemd, so it works even when your SSH session dies
- Modules: dns, bbr, sysctl, ssh, firewall, fail2ban, abuse, ipv6, mss, updates, timesync, journald, swap
- Profiles: recommended, vpn, web, bot, game, all
- Terminal output is English; reports sent to Telegram use the language of your PrivateChecker bot
- Works with PrivateChecker: after scan, apply or verify run by hand it offers to send the report to your bot,
  and `privatetoolbox integrate` adds a PrivateToolBox button to that bot (owner only)
- Optional check from Iranian probes (`verify --iran`)