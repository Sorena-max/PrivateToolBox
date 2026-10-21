"""The local link that lets a PrivateChecker bot run PrivateToolBox (owner only).

It is an ordinary journaled change: a small root service listening on a Unix
socket that only members of the `privatetoolbox` group can open, and the
`privatechecker` service user is added to that group. `privatetoolbox integrate
--remove` (or `undo`) takes it all back.
"""

from .actions import Plan, Run, Service, WriteFile
from .safety import executable

MODULE_ID = "bridge"
UNIT_NAME = "privatetoolbox-agent"
UNIT = "/etc/systemd/system/%s.service" % UNIT_NAME
GROUP = "privatetoolbox"
CHECKER_USER = "privatechecker"


def unit_text():
    return (
        "[Unit]\n"
        "Description=PrivateToolBox agent for the PrivateChecker bot\n"
        "After=network.target\n\n"
        "[Service]\n"
        "ExecStart=%s agent\n"
        "Restart=always\n"
        "RestartSec=3\n"
        "RuntimeDirectory=privatetoolbox\n"
        "RuntimeDirectoryMode=0755\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n" % executable())


def plan(ctx):
    s = ctx.system
    code, _ = s.run(["id", "-u", CHECKER_USER], timeout=10)
    if code != 0:
        return Plan(MODULE_ID, skip=("integrate_no_checker", {}))
    if s.exists(UNIT):
        return Plan(MODULE_ID, skip=("integrate_already", {}))
    actions = [
        Run(["groupadd", "-f", GROUP], undo=["groupdel", GROUP]),
        Run(["usermod", "-aG", GROUP, CHECKER_USER], undo=["gpasswd", "-d", CHECKER_USER, GROUP]),
        WriteFile(UNIT, unit_text(), undo_after=["systemctl", "daemon-reload"]),
        Run(["systemctl", "daemon-reload"], undo=["systemctl", "daemon-reload"]),
        Service(UNIT_NAME, enable=True, state="restarted"),
        # the bot has to restart to pick up its new group
        Service("privatechecker", enable=False, state="restarted"),
    ]
    return Plan(MODULE_ID, actions)
