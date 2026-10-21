"""Reads network facts: listening ports, the admin's SSH session, local addresses."""

import ipaddress
import os
import re

EPHEMERAL_UDP_SKIP = {68, 5353, 546}
ENDPOINT_RE = re.compile(r"^\[?[0-9a-fA-F:.]+\]?:\d+$")


def _scope(addr_hex):
    if set(addr_hex) == {"0"}:
        return "public"
    if addr_hex.upper() in ("0100007F", "00000000000000000000000001000000"):
        return "local"
    return "other"


def parse_proc_net(text, proto):
    """Return a set of (proto, port) bound to every address."""
    found = set()
    wanted_state = "0A" if proto == "tcp" else "07"
    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[3] != wanted_state:
            continue
        addr, _, port_hex = fields[1].rpartition(":")
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue
        if _scope(addr) == "public":
            if proto == "udp" and port in EPHEMERAL_UDP_SKIP:
                continue
            found.add((proto, port))
    return found


def public_listeners(system, proc="/proc"):
    """Ports that accept connections from the outside, as sorted (proto, port)."""
    found = set()
    for proto in ("tcp", "udp"):
        for suffix in ("", "6"):
            found |= parse_proc_net(system.read("%s/net/%s%s" % (proc, proto, suffix)), proto)
    return sorted(found, key=lambda item: (item[0], item[1]))


def parse_sshd_ports(output):
    ports = []
    for line in (output or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].lower() == "port" and parts[1].isdigit():
            ports.append(int(parts[1]))
    return ports


def ssh_ports(system, session=None):
    """Ports the SSH daemon listens on (always includes the admin's own port)."""
    code, out = system.run(["sshd", "-T"], timeout=10)
    ports = parse_sshd_ports(out) if code == 0 else []
    if session and session["server_port"] not in ports:
        ports.append(session["server_port"])
    return sorted(set(ports or [22]))


def parse_ssh_connection(value):
    parts = (value or "").split()
    if len(parts) == 4 and parts[1].isdigit() and parts[3].isdigit():
        return {"client_ip": parts[0], "client_port": int(parts[1]),
                "server_ip": parts[2], "server_port": int(parts[3])}
    return None


def parse_ss_sessions(output, pids):
    """Find the established connection owned by one of our ancestor sshd pids."""
    for line in (output or "").splitlines():
        if not any("pid=%d," % pid in line or "pid=%d)" % pid in line for pid in pids):
            continue
        # `ss` may or may not print a state column, so pick the two address:port fields
        pairs = [c for c in line.split() if ENDPOINT_RE.match(c)]
        if len(pairs) < 2:
            continue
        local, peer = pairs[0], pairs[1]
        l_ip, _, l_port = local.rpartition(":")
        p_ip, _, p_port = peer.rpartition(":")
        if l_port.isdigit() and p_port.isdigit():
            return {"client_ip": p_ip.strip("[]"), "client_port": int(p_port),
                    "server_ip": l_ip.strip("[]"), "server_port": int(l_port)}
    return None


def ancestors(system, pid=None):
    pids, pid = [], pid or os.getpid()
    for _ in range(40):
        text = system.read("/proc/%d/stat" % pid)
        if not text:
            break
        try:
            ppid = int(text.rpartition(")")[2].split()[1])
        except (IndexError, ValueError):
            break
        if ppid <= 1:
            break
        pids.append(ppid)
        pid = ppid
    return pids


def ssh_session(system):
    """The admin's own SSH connection, so we never cut it off. None if not over SSH."""
    for name in ("SSH_CONNECTION",):
        found = parse_ssh_connection(system.env(name))
        if found:
            return found
    client = system.env("SSH_CLIENT").split()
    if len(client) == 3 and client[1].isdigit() and client[2].isdigit():
        return {"client_ip": client[0], "client_port": int(client[1]),
                "server_ip": "", "server_port": int(client[2])}
    pids = ancestors(system)
    if pids:
        code, out = system.run(["ss", "-H", "-tnp", "state", "established"], timeout=10)
        if code == 0:
            return parse_ss_sessions(out, pids)
    return None


def session_is_ipv6(session):
    if not session:
        return False
    try:
        return ipaddress.ip_address(session["client_ip"]).version == 6
    except ValueError:
        return False


def local_ipv4(system):
    code, out = system.run(["ip", "-o", "-4", "addr", "show"], timeout=10)
    found = []
    for line in (out or "").splitlines() if code == 0 else []:
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            found.append(match.group(1))
    return found


def default_gateways(system):
    code, out = system.run(["ip", "-4", "route", "show", "default"], timeout=10)
    found = []
    for line in (out or "").splitlines() if code == 0 else []:
        match = re.search(r"via (\d+\.\d+\.\d+\.\d+)", line)
        if match:
            found.append(match.group(1))
    return found


def nameservers(system):
    found = []
    for path in ("/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"):
        for line in (system.read(path) or "").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == "nameserver":
                try:
                    if ipaddress.ip_address(parts[1]).version == 4:
                        found.append(parts[1])
                except ValueError:
                    pass
    return found
