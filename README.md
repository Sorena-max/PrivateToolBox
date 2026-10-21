# PrivateToolBox

Safe hardening and tuning for a fresh Linux server, in one tool. It looks at your server, shows you
exactly what it would change, applies it, and undoes everything by itself if something goes wrong.

[فارسی](README.fa.md) | [Quick guide](GUIDE.md) | [راهنمای سریع](GUIDE.fa.md)

- 🔍 **Scan** gives your server a score from 0 to 100 and changes nothing
- 🧾 **Plan first**: every change is listed before it happens, and nothing is applied without a yes
- ⏪ **Undo anything**: each run is journaled, `privatetoolbox undo` puts every file and setting back
- 🛟 **Automatic rollback** that does not need your terminal: risky changes arm a systemd timer, and if you
  do not confirm in time (even if your SSH session died) the server goes back to how it was
- 🇮🇷 Optional check that Iran can still reach the server after the change
- 🤖 Works with [PrivateChecker](https://github.com/Sorena-max/PrivateChecker): it offers to send the
  report to your Telegram bot, and you can run PrivateToolBox from a button inside that bot

The terminal is in English on purpose (terminals draw Persian badly). Reports sent to your Telegram bot use
the language of your PrivateChecker bot, Persian or English.

## Install

You need a Linux server with systemd and root access. Tested on Ubuntu 22.04+ and Debian 12+.

```bash
curl -fsSL https://raw.githubusercontent.com/Sorena-max/PrivateToolBox/main/install.sh | sudo bash
```

This only copies files to `/opt/privatetoolbox` and adds the `privatetoolbox` command. It does not change
your server. To install a fixed release, add `--ref v0.1.0` after `bash -s --`.

## Use

```bash
sudo privatetoolbox                         # interactive menu
sudo privatetoolbox scan                    # score and findings, read only
sudo privatetoolbox plan --profile vpn      # show what would change
sudo privatetoolbox apply --profile vpn     # apply (asks first, arms the rollback timer)
sudo privatetoolbox apply bbr dns           # or pick modules by name
sudo privatetoolbox undo                    # take the last run back
sudo privatetoolbox verify --iran           # check everything works, and Iran can reach you
```

What `apply` does on a server where SSH or the firewall changes:

1. shows the plan and asks
2. arms a rollback timer (default 120 seconds)
3. applies, then checks that everything works
4. asks you to open a new terminal, make sure you can still log in, and type `yes`
5. if you do not, the timer undoes the whole run

With `--yes` (for scripts) it keeps the changes only if every check passed, otherwise the timer rolls them back.

## With PrivateChecker (Telegram)

If a [PrivateChecker](https://github.com/Sorena-max/PrivateChecker) bot is running on the same server:

- **Reports:** after `scan`, `apply` or `verify` run by hand, PrivateToolBox notices it and asks
  `Send this report to your Telegram bot? [y/N]`. Nothing is sent unless you say yes (or pass `--notify`).
  Reports contain a summary and check results, never passwords, keys or tokens.
- **A button in the bot:** `sudo privatetoolbox integrate` adds a PrivateToolBox button to your bot
  (the installer offers it too). From it the **owner** can scan, preview, apply a profile, keep or undo changes.
  Applying from the bot always arms the rollback timer and waits for a Keep tap, so a bad change undoes itself.
- Remove the button any time with `sudo privatetoolbox integrate --remove`.

How the button is wired: a small root service (`privatetoolbox-agent`) listens on a Unix socket that only
the `privatetoolbox` group can open, and only the `privatechecker` service user is added to that group.
It accepts a short list of commands, checks every value against a fixed list or pattern, and runs
`privatetoolbox` without a shell, so a request cannot add its own options.

About encryption: the connection to Telegram is encrypted with TLS, but Telegram bot messages are not
end-to-end encrypted. That is why reports never include secrets.

## Modules

| Module | What it does |
|---|---|
| `dns` | Measures Cloudflare, Google, Quad9, OpenDNS and AdGuard from your server and uses the best one |
| `bbr` | Turns on BBR with the fq queue when the kernel supports it |
| `sysctl` | Safe kernel network hardening and tuning (SYN cookies, redirects, loose rp_filter, backlog ...) |
| `ssh` | Drop-in hardening (login attempts, root login, X11), optional keys only login and extra port |
| `firewall` | UFW: allows SSH first, then the ports that are already listening, plus your own |
| `fail2ban` | Bans SSH guessing, never bans you |
| `abuse` | Blocks new outgoing connections to private and reserved ranges so your provider stops sending abuse reports |
| `ipv6` | Turns IPv6 off (refuses if you are connected over IPv6) |
| `mss` | TCP MSS clamp for servers that forward traffic |
| `updates` | Automatic security updates |
| `timesync` | Makes sure the clock is synchronised |
| `journald` | Limits the size of the system log |
| `swap` | Adds a swap file on small servers |

Profiles: `recommended`, `vpn`, `web`, `bot`, `game`, `all`. See what is inside one with
`privatetoolbox plan --profile vpn`.

### Options

```text
--dns auto|keep|cloudflare|google|quad9|opendns|adguard
--ssh-port N              also listen on this SSH port (the old port stays open)
--ssh-keys-only           turn off password login (needs a key for you)
--open "443 51820/udp"    extra ports to allow
--exclude "8080"          listening ports to leave closed
--no-discover             only open SSH and the ports you name
--forward-accept          let UFW forward traffic (NAT, VPN)
--abuse-profile minimal|aggressive    and  --block-smtp
--rollback SECONDS | --no-rollback    --notify    --iran
```

## Safety

- The firewall allows your SSH port (and the one you are connected on) before it turns on.
- A new SSH port is added next to the old one; the old one is not removed.
- The abuse guard never drops replies to connections that came in, and leaves your own subnet, gateway,
  DNS servers and the cloud metadata address alone.
- Password login is only turned off when your own account has a key, and `sshd -t` must pass first.
- Config files that change are saved first. A failed step undoes everything done so far.
- The journal of every run is in `/var/lib/privatetoolbox` (readable by root only).

## Remove

```bash
sudo privatetoolbox undo          # take back what was changed
sudo privatetoolbox uninstall     # remove the program (--purge also deletes history)
```

## Development

```bash
python3 -m unittest discover -s tests -t .
```

CI runs the tests on Python 3.8 to 3.13 and runs the real tool on Ubuntu, including apply and undo.

## License

[MIT](LICENSE). This project is free. Selling it or charging money for it is prohibited.
GitHub: [Sorena-max](https://github.com/Sorena-max)
