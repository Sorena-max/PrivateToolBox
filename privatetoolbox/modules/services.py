"""Fail2Ban for SSH and unattended security updates."""

from .. import netinfo
from ..actions import Install, Plan, Service, WriteFile
from .base import Module


class Fail2Ban(Module):
    id = "fail2ban"
    weight = 14
    JAIL = "/etc/fail2ban/jail.d/privatetoolbox.local"

    def scan(self, ctx):
        if ctx.is_active("fail2ban"):
            return self.ok("f2b_on")
        return self.todo("f2b_off")

    def plan(self, ctx):
        s = ctx.system
        if not ctx.has_apt and not s.which("fail2ban-client"):
            return self.skip("f2b_unsupported")
        if self.scan(ctx).status == "ok" and s.exists(self.JAIL):
            return self.skip("f2b_on")
        ignore = ["127.0.0.1/8", "::1"]
        if ctx.ssh and ctx.ssh["client_ip"] not in ignore:
            ignore.append(ctx.ssh["client_ip"])
        ports = ",".join(str(p) for p in netinfo.ssh_ports(s, ctx.ssh)
                         + ([ctx.opts.ssh_port] if ctx.opts.ssh_port else []))
        text = ("# Managed by PrivateToolBox\n[DEFAULT]\nignoreip = %s\nbantime = 1h\n"
                "findtime = 10m\nmaxretry = 5\nbackend = systemd\n\n[sshd]\nenabled = true\nport = %s\n"
                % (" ".join(ignore), ports))
        actions = []
        if not s.which("fail2ban-client"):
            actions.append(Install(["fail2ban"]))
        actions += [WriteFile(self.JAIL, text), Service("fail2ban", enable=True, state="restarted")]
        notes = [("f2b_note", {"ignore": ", ".join(ignore)})]
        return Plan(self.id, actions, notes=notes)

    def verify(self, ctx):
        return [(ctx.is_active("fail2ban"), "f2b_verify", {})]


class Updates(Module):
    id = "updates"
    weight = 8
    CONF = "/etc/apt/apt.conf.d/20auto-upgrades"
    WANTED = 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n'

    def scan(self, ctx):
        if not ctx.has_apt:
            return self.na("upd_na")
        text = ctx.system.read(self.CONF) or ""
        if 'Unattended-Upgrade "1"' in text:
            return self.ok("upd_on")
        return self.todo("upd_off")

    def plan(self, ctx):
        finding = self.scan(ctx)
        if finding.status != "todo":
            return self.skip(finding.key)
        actions = []
        if not ctx.system.which("unattended-upgrade"):
            actions.append(Install(["unattended-upgrades"]))
        actions.append(WriteFile(self.CONF, self.WANTED))
        return Plan(self.id, actions)
