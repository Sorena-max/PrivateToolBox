from .abuse import Abuse
from .dns import Dns
from .firewall import Firewall
from .services import Fail2Ban, Updates
from .ssh import Ssh
from .tuning import Bbr, Ipv6, Journald, MssClamp, Swap, SysctlHardening, TimeSync

# Order matters: SSH settings go in before the firewall so its ports are known,
# and anything that can cut access comes after the harmless tuning.
ALL = [Dns(), Bbr(), SysctlHardening(), Ipv6(), MssClamp(), Ssh(), Firewall(),
       Fail2Ban(), Abuse(), Updates(), TimeSync(), Journald(), Swap()]
BY_ID = {m.id: m for m in ALL}

PROFILES = {
    "recommended": ["bbr", "sysctl", "ssh", "firewall", "fail2ban", "updates", "timesync", "journald"],
    "vpn": ["dns", "bbr", "sysctl", "mss", "ssh", "firewall", "fail2ban", "abuse", "updates",
            "timesync", "journald"],
    "web": ["bbr", "sysctl", "ssh", "firewall", "fail2ban", "updates", "timesync", "journald", "swap"],
    "bot": ["sysctl", "ssh", "firewall", "fail2ban", "updates", "timesync", "swap"],
    "game": ["dns", "bbr", "sysctl", "ssh", "firewall", "fail2ban", "timesync"],
    "all": [m.id for m in ALL if m.id != "ipv6"],
}


def select(ids):
    """Modules for the given ids, in safe application order."""
    wanted = set(ids)
    return [m for m in ALL if m.id in wanted]
