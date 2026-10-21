# 🧰 PrivateToolBox: quick guide

[فارسی 🇮🇷](GUIDE.fa.md) | [Full README](README.md)

Make a new server safer and faster in about 5 minutes. Nothing is changed until you say yes,
and everything can be undone. 🛟

## 🚀 Start

**1️⃣ Install** (log in to your server as root, or use `sudo`)

```bash
curl -fsSL https://raw.githubusercontent.com/Sorena-max/PrivateToolBox/main/install.sh | sudo bash
```

It only copies files and adds the `privatetoolbox` command. Your server is not touched yet.

**2️⃣ Look first 🔍**

```bash
sudo privatetoolbox scan
```

You get a score out of 100 and a list: ✔ is fine, ✖ can be improved.

**3️⃣ Preview 🧾**

```bash
sudo privatetoolbox plan --profile recommended
```

It prints every change it would make. Still nothing is changed.

**4️⃣ Apply ✅**

```bash
sudo privatetoolbox apply --profile recommended
```

Read the plan, answer `y`. When it finishes:

- 🪟 open a **new** terminal and make sure you can still log in
- ⌨️ go back to the first terminal and type `yes`

If you do nothing, after 2 minutes it **undoes everything by itself**. 🛟

## 🎯 Pick a profile

| Profile | For |
|---|---|
| `recommended` | any server: BBR, kernel hardening, SSH, firewall, Fail2Ban, updates, clock, logs |
| `vpn` | proxy or VPN servers: also DNS test, MSS clamp and the abuse guard |
| `web` | websites: recommended plus a swap file |
| `bot` | Telegram bots and small apps |
| `game` | game servers: DNS, BBR, firewall |
| `all` | everything except IPv6 |

Or choose modules yourself: `sudo privatetoolbox apply bbr dns firewall`

## 🧩 What each module does

- 🌐 `dns` tests 5 public DNS services from **your** server and uses the fastest
- 🚀 `bbr` faster connections on long routes
- 🧱 `sysctl` safer kernel network settings
- 🔐 `ssh` fewer login tries, no X11, optional keys only
- 🔥 `firewall` opens SSH and the ports already in use, closes the rest
- 🚫 `fail2ban` blocks anyone guessing your SSH password
- 🛡 `abuse` stops your server from scanning private networks, so your provider stops complaining
- ⏱ `updates`, `timesync`, `journald`, `swap` small things that keep a server healthy

## ✅ Common tasks

- 🕵️ **Open one more port:** `sudo privatetoolbox apply firewall --open "8443 51820/udp"`
- 🔑 **Passwords off, keys only:** `sudo privatetoolbox apply ssh --ssh-keys-only` (needs your key on the server)
- 🔢 **Add a second SSH port:** `sudo privatetoolbox apply ssh firewall --ssh-port 2222`
- 🏎 **Only test DNS:** `sudo privatetoolbox dns-test`
- 🇮🇷 **Can Iran reach me?** `sudo privatetoolbox verify --iran`
- 📲 **Send the result to Telegram:** with PrivateChecker on the same server it asks you after `apply` and `verify`
- 🤖 **Use it from your bot:** `sudo privatetoolbox integrate` adds a 🧰 PrivateToolBox button to your PrivateChecker
  bot (owner only). Scan, preview, apply, then tap ✅ Keep within 3 minutes or it undoes itself
- 🔌 **Remove the bot button:** `sudo privatetoolbox integrate --remove`
- ⏪ **I changed my mind:** `sudo privatetoolbox undo`
- 🕘 **What did I change before?** `sudo privatetoolbox history`

## 🆘 Problems

| Problem | What to do |
|---|---|
| 😱 I cannot log in after a change | Wait 2 minutes: the timer undoes it. Or from your provider's console run `privatetoolbox undo` |
| ⏳ "could not arm the rollback timer" | The server has no systemd. Use `--no-rollback` only if you can reach the console |
| 🔥 Docker ports are open | Docker bypasses UFW. Publish ports on `127.0.0.1` or use the `DOCKER-USER` chain |
| 🌐 DNS was not changed | Another tool manages DNS here (netplan, NetworkManager). It is left alone on purpose |
| 🧊 Nothing happens | You already have everything set. Run `scan` |

## 🔒 Good to know

- 🔍 `scan`, `plan`, `history` and `dns-test` never change anything.
- 📒 Every run is saved in `/var/lib/privatetoolbox`.
- 🆓 This project is free. Selling it or charging money for it is prohibited.

GitHub: [Sorena-max/PrivateToolBox](https://github.com/Sorena-max/PrivateToolBox)
