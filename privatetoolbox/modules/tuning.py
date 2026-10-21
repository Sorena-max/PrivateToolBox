"""Kernel and system tuning: BBR, sysctl hardening, IPv6, MSS clamp, journald, swap, time."""

import re

from .. import netinfo
from ..actions import Install, Plan, Run, Service, Sysctl, WriteFile
from .base import Module
from .nftutil import table_actions, table_exists

SYSCTL_FILE = "/etc/sysctl.d/91-privatetoolbox-net.conf"

# Safe on a server, including VPN gateways (rp_filter is loose, not strict).
HARDENING = [
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.conf.all.rp_filter", "2"),
    ("net.ipv4.conf.default.rp_filter", "2"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.secure_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv6.conf.all.accept_redirects", "0"),
    ("net.ipv6.conf.all.accept_source_route", "0"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
    ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
    ("net.ipv4.tcp_rfc1337", "1"),
    ("net.ipv4.tcp_mtu_probing", "1"),
    ("net.ipv4.tcp_fastopen", "3"),
    ("net.core.somaxconn", "4096"),
    ("net.ipv4.tcp_max_syn_backlog", "4096"),
    ("net.core.netdev_max_backlog", "16384"),
    ("kernel.dmesg_restrict", "1"),
    ("fs.protected_hardlinks", "1"),
    ("fs.protected_symlinks", "1"),
]


def _proc_path(key):
    return "/proc/sys/" + key.replace(".", "/")


class Bbr(Module):
    id = "bbr"
    weight = 6

    def scan(self, ctx):
        cc = ctx.system.sysctl_get("net.ipv4.tcp_congestion_control")
        if cc is None:
            return self.na("bbr_na_kernel")
        if cc == "bbr":
            return self.ok("bbr_on")
        return self.todo("bbr_off", current=cc)

    def plan(self, ctx):
        s = ctx.system
        cc = s.sysctl_get("net.ipv4.tcp_congestion_control")
        if cc is None:
            return self.skip("bbr_na_kernel")
        if cc == "bbr" and s.sysctl_get("net.core.default_qdisc") == "fq":
            return self.skip("bbr_on")
        actions = []
        available = (s.sysctl_get("net.ipv4.tcp_available_congestion_control") or "").split()
        if "bbr" not in available:
            code, _ = s.run(["modinfo", "tcp_bbr"], timeout=10)
            if code != 0:
                return self.skip("bbr_unsupported")
            actions += [Run(["modprobe", "tcp_bbr"]),
                        WriteFile("/etc/modules-load.d/privatetoolbox-bbr.conf", "tcp_bbr\n")]
        actions += [
            WriteFile("/etc/sysctl.d/90-privatetoolbox-bbr.conf",
                      "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n"),
            Sysctl("net.core.default_qdisc", "fq"),
            Sysctl("net.ipv4.tcp_congestion_control", "bbr"),
        ]
        return Plan(self.id, actions, notes=[("bbr_note", {})])

    def verify(self, ctx):
        cc = ctx.system.sysctl_get("net.ipv4.tcp_congestion_control")
        return [(cc == "bbr", "bbr_verify", {"current": cc})]


class SysctlHardening(Module):
    id = "sysctl"
    weight = 10

    def _wanted(self, ctx):
        return [(k, v) for k, v in HARDENING if ctx.system.exists(_proc_path(k))]

    def scan(self, ctx):
        wanted = self._wanted(ctx)
        if not wanted:
            return self.na("bbr_na_kernel")
        wrong = [k for k, v in wanted if ctx.system.sysctl_get(k) != v]
        if not wrong:
            return self.ok("sysctl_ok")
        return self.todo("sysctl_todo", count=len(wrong))

    def plan(self, ctx):
        s = ctx.system
        wanted = self._wanted(ctx)
        differing = [(k, v) for k, v in wanted if s.sysctl_get(k) != v]
        if not differing:
            return self.skip("sysctl_ok")
        text = "# Managed by PrivateToolBox\n" + "".join("%s = %s\n" % kv for kv in wanted)
        actions = [WriteFile(SYSCTL_FILE, text)] + [Sysctl(k, v) for k, v in differing]
        return Plan(self.id, actions, notes=[("sysctl_note", {"count": len(differing)})])

    def verify(self, ctx):
        wrong = [k for k, v in self._wanted(ctx) if ctx.system.sysctl_get(k) != v]
        return [(not wrong, "sysctl_verify", {"count": len(wrong)})]


class Ipv6(Module):
    id = "ipv6"
    weight = 0

    def scan(self, ctx):
        value = ctx.system.sysctl_get("net.ipv6.conf.all.disable_ipv6")
        if value is None:
            return self.na("ipv6_na")
        return self.info("ipv6_off" if value == "1" else "ipv6_on")

    def plan(self, ctx):
        s = ctx.system
        if s.sysctl_get("net.ipv6.conf.all.disable_ipv6") is None:
            return self.skip("ipv6_na")
        if s.sysctl_get("net.ipv6.conf.all.disable_ipv6") == "1":
            return self.skip("ipv6_off")
        if netinfo.session_is_ipv6(ctx.ssh):
            return self.skip("ipv6_ssh_session")
        keys = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"]
        text = "# Managed by PrivateToolBox\n" + "".join("%s = 1\n" % k for k in keys)
        actions = [WriteFile("/etc/sysctl.d/92-privatetoolbox-ipv6.conf", text)]
        actions += [Sysctl(k, "1") for k in keys]
        return Plan(self.id, actions, notes=[("ipv6_note", {})])


class MssClamp(Module):
    id = "mss"
    weight = 3
    TABLE = "privatetoolbox_mss"
    CONF = "/etc/privatetoolbox/mss.nft"

    def scan(self, ctx):
        if ctx.system.sysctl_get("net.ipv4.ip_forward") != "1":
            return self.na("mss_not_router")
        if table_exists(ctx.system, self.TABLE):
            return self.ok("mss_on")
        return self.todo("mss_off")

    def plan(self, ctx):
        if table_exists(ctx.system, self.TABLE):
            return self.skip("mss_on")
        text = (
            "table inet %(t)s\ndelete table inet %(t)s\n"
            "table inet %(t)s {\n  chain forward {\n"
            "    type filter hook forward priority mangle; policy accept;\n"
            "    tcp flags syn tcp option maxseg size set rt mtu\n  }\n}\n" % {"t": self.TABLE})
        actions = table_actions(ctx, "privatetoolbox-mss", "PrivateToolBox TCP MSS clamp",
                                self.CONF, text, self.TABLE)
        return Plan(self.id, actions, notes=[("mss_note", {})])


class Journald(Module):
    id = "journald"
    weight = 2
    CONF = "/etc/systemd/journald.conf.d/privatetoolbox.conf"

    def scan(self, ctx):
        s = ctx.system
        texts = [s.read("/etc/systemd/journald.conf") or ""]
        for name in s.listdir("/etc/systemd/journald.conf.d"):
            texts.append(s.read("/etc/systemd/journald.conf.d/" + name) or "")
        if any(re.search(r"^\s*SystemMaxUse\s*=", t, re.M) for t in texts):
            return self.ok("journald_ok")
        return self.todo("journald_todo")

    def plan(self, ctx):
        if self.scan(ctx).status == "ok":
            return self.skip("journald_ok")
        text = "# Managed by PrivateToolBox\n[Journal]\nSystemMaxUse=200M\nMaxRetentionSec=1month\n"
        return Plan(self.id, [WriteFile(self.CONF, text, after=["systemctl", "restart", "systemd-journald"],
                                        undo_after=["systemctl", "restart", "systemd-journald"])])


class Swap(Module):
    id = "swap"
    weight = 4
    FILE = "/swapfile"

    def _mem_kb(self, ctx):
        info = {}
        for line in (ctx.system.read("/proc/meminfo") or "").splitlines():
            key, _, rest = line.partition(":")
            parts = rest.split()
            if parts and parts[0].isdigit():
                info[key] = int(parts[0])
        return info.get("MemTotal", 0), info.get("SwapTotal", 0)

    def scan(self, ctx):
        mem, swap = self._mem_kb(ctx)
        if not mem:
            return self.na("swap_na")
        if swap > 0:
            return self.ok("swap_ok")
        if mem > 4 * 1024 * 1024:
            return self.na("swap_not_needed")
        return self.todo("swap_todo", mem_mb=mem // 1024)

    def plan(self, ctx):
        s = ctx.system
        finding = self.scan(ctx)
        if finding.status != "todo":
            return self.skip(finding.key, **finding.params)
        size = int(ctx.opts.swap_mb)
        if s.free_bytes("/") < (size + 512) * 1024 * 1024:
            return self.skip("swap_no_space")
        fstab = s.read("/etc/fstab") or ""
        if not fstab.endswith("\n") and fstab:
            fstab += "\n"
        actions = [
            Run(["fallocate", "-l", "%dM" % size, self.FILE], undo=["rm", "-f", self.FILE]),
            Run(["chmod", "600", self.FILE]),
            Run(["mkswap", self.FILE]),
            Run(["swapon", self.FILE], undo=["swapoff", self.FILE]),
            WriteFile("/etc/fstab", fstab + "%s none swap sw 0 0\n" % self.FILE, mode=0o644),
        ]
        return Plan(self.id, actions, notes=[("swap_note", {"size": size})])


class TimeSync(Module):
    id = "timesync"
    weight = 4

    def scan(self, ctx):
        code, out = ctx.system.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=10)
        if code != 0:
            return self.na("time_na")
        return self.ok("time_ok") if out.strip() == "yes" else self.todo("time_todo")

    def plan(self, ctx):
        s = ctx.system
        finding = self.scan(ctx)
        if finding.status != "todo":
            return self.skip(finding.key)
        if s.exists("/lib/systemd/system/systemd-timesyncd.service") or \
                s.exists("/usr/lib/systemd/system/systemd-timesyncd.service"):
            return Plan(self.id, [Service("systemd-timesyncd", enable=True, state="restarted"),
                                  Run(["timedatectl", "set-ntp", "true"],
                                      undo=["timedatectl", "set-ntp", "false"])])
        return Plan(self.id, [Install(["chrony"]), Service("chrony", enable=True, state="restarted")])
