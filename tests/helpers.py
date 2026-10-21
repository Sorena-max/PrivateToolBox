"""A fake machine for tests: files, commands and /proc values live in memory."""

import io
import os
import tempfile

from privatetoolbox.ui import UI


class FakeSystem:
    def __init__(self, files=None, env=None, bins=(), root=True, responses=None):
        self.files = {}
        self.modes = {}
        for path, content in (files or {}).items():
            self.files[path] = content.encode("utf-8") if isinstance(content, str) else content
        self.env_vars = dict(env or {})
        self.bins = set(bins)
        self.root = root
        self.responses = list(responses or [])    # [(command prefix tuple, (code, output))]
        self.commands = []
        self.links = set()
        self.clock = 1_700_000_000.0
        self.fail_on = None                         # command prefix that should fail

    # files
    def read_bytes(self, path):
        return self.files.get(path)

    def read(self, path):
        data = self.files.get(path)
        return None if data is None else data.decode("utf-8")

    def write(self, path, content, mode=0o644):
        self.files[path] = content.encode("utf-8") if isinstance(content, str) else content
        self.modes[path] = mode

    def mode(self, path):
        return self.modes.get(path) if path in self.files else None

    def remove(self, path):
        self.files.pop(path, None)
        self.modes.pop(path, None)

    def exists(self, path):
        return path in self.files or any(p.startswith(path.rstrip("/") + "/") for p in self.files)

    def islink(self, path):
        return path in self.links

    def listdir(self, path):
        prefix = path.rstrip("/") + "/"
        names = {p[len(prefix):].split("/")[0] for p in self.files if p.startswith(prefix)}
        return sorted(names)

    # commands
    def run(self, cmd, timeout=60):
        self.commands.append(list(cmd))
        if self.fail_on and list(cmd[:len(self.fail_on)]) == list(self.fail_on):
            return 1, "simulated failure"
        if list(cmd[:2]) == ["sysctl", "-w"] and "=" in cmd[2]:
            key, _, value = cmd[2].partition("=")
            self.set_sysctl(key, value)
        for prefix, result in self.responses:
            if list(cmd[:len(prefix)]) == list(prefix):
                return result
        return 0, ""

    def ran(self, *prefix):
        return any(c[:len(prefix)] == list(prefix) for c in self.commands)

    def which(self, name):
        return "/usr/bin/" + name if name in self.bins else None

    def is_root(self):
        return self.root

    def env(self, name, default=""):
        return self.env_vars.get(name, default)

    def sysctl_get(self, key):
        text = self.read("/proc/sys/" + key.replace(".", "/"))
        return None if text is None else text.strip()

    def set_sysctl(self, key, value):
        self.files["/proc/sys/" + key.replace(".", "/")] = (str(value) + "\n").encode()

    def now(self):
        self.clock += 1
        return self.clock

    def free_bytes(self, path):
        return 50 * 1024 ** 3


def server(**kw):
    """A plausible fresh Ubuntu server."""
    files = {
        "/etc/os-release": 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04.4 LTS"\n',
        "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n",
        "/etc/ssh/sshd_config.d/50-cloud-init.conf": "PasswordAuthentication yes\n",
        "/etc/default/ufw": 'IPV6=yes\nDEFAULT_FORWARD_POLICY="DROP"\n',
        "/etc/ufw/ufw.conf": "ENABLED=no\n",
        "/proc/meminfo": "MemTotal:  1008000 kB\nSwapTotal:  0 kB\n",
        "/proc/net/tcp": ("  sl  local_address rem_address   st\n"
                          "   0: 00000000:0016 00000000:0000 0A\n"
                          "   1: 00000000:01BB 00000000:0000 0A\n"
                          "   2: 0100007F:1538 00000000:0000 0A\n"),
        "/proc/net/tcp6": "  sl  local_address rem_address   st\n",
        "/proc/net/udp": ("  sl  local_address rem_address   st\n"
                          "   0: 00000000:CA6C 00000000:0000 07\n"
                          "   1: 00000000:0044 00000000:0000 07\n"),
        "/proc/net/udp6": "  sl  local_address rem_address   st\n",
        "/etc/resolv.conf": "nameserver 10.0.0.2\n",
        "/etc/fstab": "UUID=abc / ext4 defaults 0 1\n",
        "/root/.ssh/authorized_keys": "ssh-ed25519 AAAAkey admin@laptop\n",
        "/lib/systemd/system/ssh.service": "",
    }
    sysctls = {"net.ipv4.tcp_congestion_control": "cubic", "net.core.default_qdisc": "pfifo_fast",
               "net.ipv4.tcp_available_congestion_control": "reno cubic bbr",
               "net.ipv4.ip_forward": "0", "net.ipv6.conf.all.disable_ipv6": "0",
               "net.ipv4.tcp_syncookies": "0", "net.ipv4.conf.all.rp_filter": "0",
               "net.ipv4.conf.default.rp_filter": "0", "net.core.somaxconn": "128"}
    files.update(kw.pop("files", {}))
    bins = {"sshd", "ssh", "ufw", "apt-get", "nft", "fail2ban-client", "unattended-upgrade"}
    bins |= set(kw.pop("bins", ()))
    responses = list(kw.pop("responses", [])) + [
        (("sshd", "-T"), (0, "port 22\npermitrootlogin yes\nmaxauthtries 6\nx11forwarding yes\n"
                             "passwordauthentication yes\n")),
        (("ufw", "status"), (0, "Status: inactive\n")),
        (("ssh", "-V"), (0, "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\n")),
        (("systemctl", "is-active"), (3, "inactive\n")),
        (("systemctl", "is-enabled"), (1, "disabled\n")),
        (("nft", "list"), (1, "no such table")),
        (("ip", "-o", "-4", "addr"), (0, "2: eth0    inet 10.0.0.5/24 brd 10.0.0.255 scope global eth0\n")),
        (("ip", "-4", "route"), (0, "default via 10.0.0.1 dev eth0\n")),
        (("timedatectl", "show"), (0, "no\n")),
    ]
    system = FakeSystem(files, env=kw.pop("env", {"SSH_CONNECTION": "203.0.113.9 50000 10.0.0.5 22"}),
                        bins=bins, responses=responses, **kw)
    for key, value in sysctls.items():
        system.set_sysctl(key, value)
    return system


def quiet_ui():
    stream = io.StringIO()
    return UI(stream=stream, color=False, utf8=False), stream


def temp_home():
    return tempfile.mkdtemp()
