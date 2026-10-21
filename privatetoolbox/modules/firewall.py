"""Firewall (UFW): allow what is already listening, always keep SSH open."""

import re

from .. import netinfo
from ..actions import Install, Plan, Run, Snapshot, WriteFile
from .base import Module

PORT_RE = re.compile(r"^(\d{1,5})(?::(\d{1,5}))?(?:/(tcp|udp))?$")
UFW_FILES = ["/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules",
             "/etc/default/ufw", "/etc/ufw/before.rules", "/etc/ufw/after.rules"]


def normalize_port(spec):
    """Return a UFW-ready rule like '443/tcp' or '1000:2000/tcp', or None if invalid."""
    match = PORT_RE.match(spec.strip())
    if not match:
        return None
    low, high, proto = match.groups()
    low_n = int(low)
    high_n = int(high) if high else low_n
    if not (1 <= low_n <= 65535 and 1 <= high_n <= 65535 and low_n <= high_n):
        return None
    base = "%d:%d" % (low_n, high_n) if high else str(low_n)
    if high and not proto:
        proto = "tcp"      # UFW requires a protocol for ranges
    return "%s/%s" % (base, proto) if proto else base


def excluded(exclude_specs, proto, port):
    for spec in exclude_specs:
        spec = spec.strip().lower()
        if spec in (str(port), "%s/%d" % (proto, port), "%d/%s" % (port, proto)):
            return True
    return False


class Firewall(Module):
    id = "firewall"
    weight = 22

    def _status(self, ctx):
        code, out = ctx.system.run(["ufw", "status"], timeout=15)
        return code == 0 and "Status: active" in out, code

    def scan(self, ctx):
        s = ctx.system
        if s.which("ufw"):
            active, _ = self._status(ctx)
            return self.ok("fw_on") if active else self.todo("fw_off")
        if ctx.is_active("firewalld"):
            return self.ok("fw_firewalld")
        return self.todo("fw_missing")

    def rules(self, ctx):
        """Ordered, de-duplicated list of UFW rules to allow, plus invalid inputs."""
        o = ctx.opts
        rules, bad = [], []

        def add(rule):
            if rule not in rules:
                rules.append(rule)

        for port in netinfo.ssh_ports(ctx.system, ctx.ssh):
            add("%d/tcp" % port)
        if o.ssh_port:
            add("%d/tcp" % o.ssh_port)
        if o.discover:
            for proto, port in netinfo.public_listeners(ctx.system):
                if not excluded(o.exclude_ports, proto, port):
                    add("%d/%s" % (port, proto))
        for spec in o.extra_ports:
            rule = normalize_port(spec)
            if rule is None:
                bad.append(spec)
            else:
                add(rule)
        return rules, bad

    def plan(self, ctx):
        s = ctx.system
        if ctx.is_active("firewalld"):
            return self.skip("fw_firewalld")
        rules, bad = self.rules(ctx)
        warnings = [("fw_bad_port", {"spec": spec}) for spec in bad]
        if s.which("docker"):
            warnings.append(("fw_docker", {}))
        actions = []
        was_active = False
        if s.which("ufw"):
            was_active, _ = self._status(ctx)
        else:
            actions.append(Install(["ufw"]))
        undo = ["ufw", "reload"] if was_active else ["ufw", "--force", "disable"]
        actions.append(Snapshot(list(UFW_FILES), undo_after=undo))
        actions.append(Run(["ufw", "default", "deny", "incoming"]))
        actions.append(Run(["ufw", "default", "allow", "outgoing"]))
        for rule in rules:
            actions.append(Run(["ufw", "allow", rule, "comment", "privatetoolbox"]))

        forwarding = s.sysctl_get("net.ipv4.ip_forward") == "1"
        wants_forward = ctx.opts.forward_accept if ctx.opts.forward_accept is not None else forwarding
        default_file = s.read("/etc/default/ufw")
        if wants_forward and default_file and 'DEFAULT_FORWARD_POLICY="DROP"' in default_file:
            actions.append(WriteFile("/etc/default/ufw", default_file.replace(
                'DEFAULT_FORWARD_POLICY="DROP"', 'DEFAULT_FORWARD_POLICY="ACCEPT"'), mode=0o644))
            warnings.append(("fw_forward_changed", {}))
        elif forwarding and not wants_forward:
            warnings.append(("fw_forward_kept", {}))

        actions.append(Run(["ufw", "--force", "enable"]))
        notes = [("fw_rules", {"rules": ", ".join(rules)})]
        return Plan(self.id, actions, notes=notes, warnings=warnings)

    def verify(self, ctx):
        active, _ = self._status(ctx)
        results = [(active, "fw_verify_active", {})]
        code, out = ctx.system.run(["ufw", "status"], timeout=15)
        for port in netinfo.ssh_ports(ctx.system, ctx.ssh):
            allowed = code == 0 and re.search(r"^%d(/tcp)?\s+ALLOW" % port, out, re.M) is not None
            results.append((allowed, "fw_verify_ssh", {"port": port}))
        return results
