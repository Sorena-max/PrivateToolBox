"""What a module needs to know about the machine and the user's choices."""

from dataclasses import dataclass, field

from . import netinfo


@dataclass
class Options:
    ssh_port: int = None            # extra SSH port to listen on
    ssh_keys_only: bool = False     # turn off password logins
    extra_ports: list = field(default_factory=list)    # "443", "51820/udp", "1000:2000/tcp"
    exclude_ports: list = field(default_factory=list)  # "tcp/8080" style, never opened
    discover: bool = True           # open the ports that are already listening
    dns: str = "auto"               # auto | keep | cloudflare | google | quad9 | opendns | adguard
    abuse_profile: str = "minimal"  # minimal | aggressive
    abuse_block_smtp: bool = False
    swap_mb: int = 1024
    forward_accept: bool = None     # None = decide from ip_forward


class Context:
    def __init__(self, system, opts=None, dns_benchmark=None):
        self.system = system
        self.opts = opts or Options()
        self.dns_benchmark = dns_benchmark
        self.os_id, self.os_version, self.os_name = self._os_release()
        self.ssh = netinfo.ssh_session(system)

    def _os_release(self):
        values = {}
        for line in (self.system.read("/etc/os-release") or "").splitlines():
            key, _, value = line.partition("=")
            values[key] = value.strip().strip('"')
        return (values.get("ID", "linux"), values.get("VERSION_ID", ""),
                values.get("PRETTY_NAME", "Linux"))

    @property
    def has_apt(self):
        return bool(self.system.which("apt-get"))

    @property
    def has_systemd(self):
        return self.system.exists("/run/systemd/system")

    @property
    def tested_os(self):
        try:
            major = int(self.os_version.split(".")[0])
        except ValueError:
            return False
        return (self.os_id == "ubuntu" and major >= 22) or (self.os_id == "debian" and major >= 12)

    def service_name_ssh(self):
        for unit in ("/lib/systemd/system/ssh.service", "/usr/lib/systemd/system/ssh.service",
                     "/etc/systemd/system/ssh.service"):
            if self.system.exists(unit):
                return "ssh"
        return "sshd"

    def is_active(self, unit):
        code, out = self.system.run(["systemctl", "is-active", unit])
        return out.strip() == "active"
