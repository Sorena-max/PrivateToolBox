"""Automatic rollback that does not depend on your terminal.

Risky changes (SSH, firewall, DNS, egress rules) arm a systemd timer first. If
you do not confirm in time, the timer runs `undo` itself, even if your SSH
session died, so a bad change can never lock you out for good.
"""

import os

DEFAULT_SECONDS = 120
ACCESS_MODULES = ("ssh", "firewall", "dns", "abuse", "ipv6", "mss")


def unit_name(run_id):
    return "privatetoolbox-rollback-%s" % run_id


def executable():
    return os.environ.get("PRIVATETOOLBOX_EXE", "/usr/local/bin/privatetoolbox")


def needs_rollback(modules):
    return any(m in ACCESS_MODULES for m in modules)


def arm(system, run_id, seconds):
    """Schedule `undo` after `seconds`. Returns True when the timer is armed."""
    cmd = ["systemd-run", "--unit", unit_name(run_id), "--on-active=%d" % seconds,
           "--description=PrivateToolBox automatic rollback",
           executable(), "undo", run_id, "--quiet"]
    code, _ = system.run(cmd, timeout=20)
    return code == 0


def pending(system, run_id):
    code, out = system.run(["systemctl", "is-active", unit_name(run_id) + ".timer"])
    return out.strip() == "active"


def confirm(system, run_id):
    """Keep the changes: cancel the pending rollback."""
    code, _ = system.run(["systemctl", "stop", unit_name(run_id) + ".timer"])
    return code == 0


def pending_run(system, engine):
    """The newest run whose rollback timer is still counting down, if any."""
    for run_id in reversed(engine.run_ids()):
        if pending(system, run_id):
            return run_id
    return None
