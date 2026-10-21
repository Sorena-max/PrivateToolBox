"""DNS: measure public resolvers from this server and use the best one."""

import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from .. import netinfo
from ..actions import Plan, WriteFile
from .base import Module

RESOLVERS = {
    "cloudflare": ("1.1.1.1", "1.0.0.1"),
    "google": ("8.8.8.8", "8.8.4.4"),
    "quad9": ("9.9.9.9", "149.112.112.112"),
    "opendns": ("208.67.222.222", "208.67.220.220"),
    "adguard": ("94.140.14.14", "94.140.15.15"),
}
NAMES = ("example.com", "wikipedia.org", "github.com", "cloudflare.com", "debian.org")
RESOLVED_CONF = "/etc/systemd/resolved.conf.d/privatetoolbox.conf"


def build_query(name, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split("."))
    return header + labels + b"\x00" + struct.pack(">HH", 1, 1)


def answer_ok(data, qid):
    if len(data) < 12:
        return False
    rid, flags, _, ancount = struct.unpack(">HHHH", data[:8])
    return rid == qid and (flags & 0x000F) == 0 and ancount > 0


def query_once(server, name, timeout=2.0):
    """Milliseconds for one A query, or None when it failed."""
    qid = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        started = time.time()
        sock.sendto(build_query(name, qid), (server, 53))
        data, _ = sock.recvfrom(2048)
        if answer_ok(data, qid):
            return (time.time() - started) * 1000
    except OSError:
        pass
    finally:
        sock.close()
    return None


def benchmark(resolvers=None, names=NAMES, rounds=2, query=query_once):
    """Rank resolvers: fewest failures first, then the lowest median latency."""
    resolvers = resolvers or RESOLVERS

    def measure(item):
        rid, ips = item
        times, fails = [], 0
        for _ in range(rounds):
            for name in names:
                ms = query(ips[0], name)
                if ms is None:
                    fails += 1
                else:
                    times.append(ms)
        times.sort()
        median = times[len(times) // 2] if times else None
        return {"id": rid, "ips": list(ips), "median_ms": median,
                "fail": fails, "total": rounds * len(names)}

    with ThreadPoolExecutor(max_workers=len(resolvers)) as pool:
        results = list(pool.map(measure, resolvers.items()))
    results.sort(key=lambda r: (r["fail"], r["median_ms"] if r["median_ms"] is not None else 1e9))
    return results


class Dns(Module):
    id = "dns"
    weight = 0

    def scan(self, ctx):
        servers = netinfo.nameservers(ctx.system)
        return self.info("dns_current", servers=", ".join(servers) or "?")

    def plan(self, ctx):
        s = ctx.system
        choice = ctx.opts.dns
        if choice == "keep":
            return self.skip("dns_keep")
        results = (ctx.dns_benchmark or benchmark)()
        usable = [r for r in results if r["fail"] == 0 and r["median_ms"] is not None]
        if choice != "auto":
            picked = next((r for r in results if r["id"] == choice), None)
            if picked is None or picked["median_ms"] is None:
                return self.skip("dns_unreachable", name=choice)
        else:
            if not usable:
                return self.skip("dns_none_usable")
            picked = usable[0]
        others = [r for r in results if r["id"] != picked["id"] and r["fail"] == 0
                  and r["median_ms"] is not None][:2]
        top = ", ".join("%s %.0f ms" % (r["id"], r["median_ms"]) for r in results
                        if r["median_ms"] is not None)
        notes = [("dns_ranking", {"ranking": top}), ("dns_picked", {"name": picked["id"]})]

        if s.exists("/lib/systemd/system/systemd-resolved.service") or \
                s.exists("/usr/lib/systemd/system/systemd-resolved.service"):
            fallback = " ".join(ip for r in others for ip in r["ips"])
            text = ("# Managed by PrivateToolBox\n[Resolve]\nDNS=%s\nFallbackDNS=%s\nDomains=~.\n"
                    % (" ".join(picked["ips"]), fallback))
            restart = ["systemctl", "restart", "systemd-resolved"]
            return Plan(self.id, [WriteFile(RESOLVED_CONF, text, after=restart, undo_after=restart)],
                        notes=notes)
        if s.islink("/etc/resolv.conf"):
            return self.skip("dns_managed")
        lines = "".join("nameserver %s\n" % ip for ip in picked["ips"])
        return Plan(self.id, [WriteFile("/etc/resolv.conf", "# Managed by PrivateToolBox\n" + lines)],
                    notes=notes)

    def verify(self, ctx):
        code, _ = ctx.system.run(["getent", "hosts", "example.com"], timeout=15)
        return [(code == 0, "dns_verify", {})]
