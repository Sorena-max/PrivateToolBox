"""Shared pieces for modules that load a small nftables table at boot."""

from ..actions import Install, Run, Service, WriteFile


def unit_text(description, conf_path, table, nft="/usr/sbin/nft"):
    return (
        "[Unit]\n"
        "Description=%s\n"
        "After=network-pre.target\n"
        "Before=network.target\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        "RemainAfterExit=yes\n"
        "ExecStart=%s -f %s\n"
        "ExecStop=-%s delete table inet %s\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n" % (description, nft, conf_path, nft, table))


def table_actions(ctx, unit, description, conf_path, conf_text, table):
    """Actions that install, load and enable an nftables table."""
    system = ctx.system
    nft = system.which("nft") or "/usr/sbin/nft"
    unit_path = "/etc/systemd/system/%s.service" % unit
    actions = []
    if not system.which("nft"):
        actions.append(Install(["nftables"]))
    actions += [
        WriteFile(conf_path, conf_text, mode=0o600),
        WriteFile(unit_path, unit_text(description, conf_path, table, nft),
                  undo_after=["systemctl", "daemon-reload"]),
        Run(["systemctl", "daemon-reload"], undo=["systemctl", "daemon-reload"]),
        Service(unit, enable=True, state="restarted"),
    ]
    return actions


def table_exists(system, table):
    code, _ = system.run(["nft", "list", "table", "inet", table], timeout=10)
    return code == 0
