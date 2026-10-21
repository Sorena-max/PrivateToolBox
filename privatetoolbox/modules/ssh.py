"""SSH hardening through a drop-in file; keys-only login only when a key exists."""

import re

from .. import netinfo
from ..actions import Plan, Run, WriteFile
from .base import Module

DROPIN = "/etc/ssh/sshd_config.d/00-privatetoolbox.conf"


def parse_sshd_t(output):
    values = {}
    for line in (output or "").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            values.setdefault(parts[0].lower(), parts[1].strip())
    return values


def openssh_version(text):
    match = re.search(r"OpenSSH_(\d+)\.(\d+)", text or "")
    return (int(match.group(1)), int(match.group(2))) if match else (0, 0)


def has_key(content):
    return any(line.strip() and not line.lstrip().startswith("#")
               for line in (content or "").splitlines())


class Ssh(Module):
    id = "ssh"
    weight = 20

    def _admin_keys_file(self, ctx):
        user = ctx.system.env("SUDO_USER") or "root"
        return "/root/.ssh/authorized_keys" if user == "root" else "/home/%s/.ssh/authorized_keys" % user

    def _any_keys(self, ctx):
        s = ctx.system
        paths = ["/root/.ssh/authorized_keys"] + [
            "/home/%s/.ssh/authorized_keys" % name for name in s.listdir("/home")]
        return any(has_key(s.read(p)) for p in paths)

    def scan(self, ctx):
        code, out = ctx.system.run(["sshd", "-T"], timeout=10)
        if code != 0:
            return self.na("ssh_na")
        v = parse_sshd_t(out)
        weak = []
        if v.get("permitrootlogin", "").lower() == "yes":
            weak.append("root")
        tries = v.get("maxauthtries", "6")
        if tries.isdigit() and int(tries) > 4:
            weak.append("tries")
        if v.get("x11forwarding", "").lower() == "yes":
            weak.append("x11")
        if not weak:
            return self.ok("ssh_ok", password=v.get("passwordauthentication", "?"))
        return self.todo("ssh_todo", weak=", ".join(weak))

    def plan(self, ctx):
        s = ctx.system
        main = s.read("/etc/ssh/sshd_config") or ""
        if not s.exists("/etc/ssh/sshd_config.d") or not re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d", main, re.M):
            return self.skip("ssh_no_dropin")
        if not s.which("sshd"):
            return self.skip("ssh_na")
        warnings, notes = [], []
        lines = ["# Managed by PrivateToolBox"]
        keys_exist = self._any_keys(ctx)
        if keys_exist:
            lines.append("PermitRootLogin prohibit-password")
        else:
            warnings.append(("ssh_root_kept", {}))
        lines += ["MaxAuthTries 3", "LoginGraceTime 30", "X11Forwarding no",
                  "PermitEmptyPasswords no", "ClientAliveInterval 120", "ClientAliveCountMax 3"]

        if ctx.opts.ssh_keys_only:
            admin_file = self._admin_keys_file(ctx)
            if has_key(s.read(admin_file)):
                _, version_text = s.run(["ssh", "-V"], timeout=10)
                modern = openssh_version(version_text) >= (8, 7)
                lines += ["PasswordAuthentication no",
                          "KbdInteractiveAuthentication no" if modern else "ChallengeResponseAuthentication no"]
                notes.append(("ssh_keys_only", {}))
            else:
                warnings.append(("ssh_no_admin_key", {"file": admin_file}))

        if ctx.opts.ssh_port:
            ports = netinfo.ssh_ports(s, ctx.ssh)
            if ctx.opts.ssh_port not in ports:
                ports.append(ctx.opts.ssh_port)
            lines += ["Port %d" % p for p in ports]
            notes.append(("ssh_ports", {"ports": ", ".join(str(p) for p in ports)}))

        service = ctx.service_name_ssh()
        # Reload only a running daemon; a stopped one reads the file when it starts.
        reload_cmd = ["systemctl", "reload", service] if ctx.is_active(service) else None
        actions = []
        if not s.exists("/run/sshd"):
            # `sshd -t` needs its privilege separation directory, which only exists
            # while the daemon runs.
            actions.append(Run(["mkdir", "-p", "/run/sshd"], undo=["rmdir", "/run/sshd"]))
        actions.append(WriteFile(DROPIN, "\n".join(lines) + "\n", validate=["sshd", "-t"],
                                 after=reload_cmd, undo_after=reload_cmd))
        return Plan(self.id, actions, notes=notes, warnings=warnings)

    def verify(self, ctx):
        code, out = ctx.system.run(["sshd", "-T"], timeout=10)
        if code != 0:
            return [(False, "ssh_verify_cfg", {})]
        v = parse_sshd_t(out)
        return [(v.get("maxauthtries") == "3", "ssh_verify_cfg", {})]
