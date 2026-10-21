"""Stop the server from talking to private and reserved ranges.

Hosting providers send abuse reports when a server scans internal networks.
This blocks those destinations on the way out, except the addresses the server
itself needs: its own subnets, gateway, DNS servers and the cloud metadata IP.
"""

import ipaddress

from ..actions import Plan
from .base import Module
from .nftutil import table_actions, table_exists

MINIMAL = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
AGGRESSIVE = MINIMAL + ["100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
                        "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"]
METADATA = "169.254.169.254/32"


def subtract(networks, hole):
    result = []
    for net in networks:
        if not net.overlaps(hole):
            result.append(net)
        elif hole.subnet_of(net):
            result.extend(net.address_exclude(hole))
        # a hole that covers the whole network removes it
    return result


def blocked_networks(profile, protect_addresses):
    """Block list for `profile` with a /24 carved out around every protected address."""
    base = AGGRESSIVE if profile == "aggressive" else MINIMAL
    nets = [ipaddress.ip_network(c) for c in base]
    holes = [ipaddress.ip_network(METADATA)]
    for addr in protect_addresses:
        try:
            holes.append(ipaddress.ip_network("%s/24" % addr, strict=False))
        except ValueError:
            continue
    for hole in holes:
        nets = subtract(nets, hole)
    return sorted(ipaddress.collapse_addresses(nets), key=lambda n: (int(n.network_address), n.prefixlen))


def render_nft(table, networks, block_smtp):
    elements = ", ".join(str(n) for n in networks)
    lines = ["table inet %s" % table, "delete table inet %s" % table,
             "table inet %s {" % table,
             "  set blocked4 {", "    type ipv4_addr", "    flags interval",
             "    elements = { %s }" % elements, "  }",
             "  chain output {", "    type filter hook output priority 0; policy accept;",
             "    ct state established,related accept",
             "    ip daddr @blocked4 counter drop"]
    if block_smtp:
        lines.append("    tcp dport { 25, 465, 587 } counter drop")
    lines += ["  }", "}", ""]
    return "\n".join(lines)


class Abuse(Module):
    id = "abuse"
    weight = 6
    TABLE = "privatetoolbox_abuse"
    CONF = "/etc/privatetoolbox/abuse.nft"

    def scan(self, ctx):
        if table_exists(ctx.system, self.TABLE):
            return self.ok("abuse_on")
        return self.todo("abuse_off")

    def protected(self, ctx):
        from .. import netinfo
        s = ctx.system
        return netinfo.local_ipv4(s) + netinfo.default_gateways(s) + netinfo.nameservers(s)

    def plan(self, ctx):
        profile = ctx.opts.abuse_profile
        if profile not in ("minimal", "aggressive"):
            return self.skip("abuse_bad_profile", profile=profile)
        nets = blocked_networks(profile, self.protected(ctx))
        text = render_nft(self.TABLE, nets, ctx.opts.abuse_block_smtp)
        actions = table_actions(ctx, "privatetoolbox-abuse", "PrivateToolBox egress abuse guard",
                                self.CONF, text, self.TABLE)
        notes = [("abuse_note", {"count": len(nets), "profile": profile})]
        warnings = [("abuse_smtp", {})] if ctx.opts.abuse_block_smtp else []
        return Plan(self.id, actions, notes=notes, warnings=warnings)

    def verify(self, ctx):
        return [(table_exists(ctx.system, self.TABLE), "abuse_verify", {})]
