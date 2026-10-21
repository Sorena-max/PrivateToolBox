"""The small set of things a module can ask the engine to do.

Modules only describe changes; the engine applies them and remembers how to
take each one back.
"""

from dataclasses import dataclass, field


@dataclass
class WriteFile:
    path: str
    content: str
    mode: int = 0o644
    validate: list = None      # command that must succeed after writing
    after: list = None         # command to run after writing (reload a service)
    undo_after: list = None    # command to run after the old file is put back

    def summary(self):
        return "write %s" % self.path


@dataclass
class Snapshot:
    """Remember files that a later command will change."""
    paths: list
    undo_after: list = None

    def summary(self):
        return "back up %s" % ", ".join(self.paths)


@dataclass
class Sysctl:
    key: str
    value: str

    def summary(self):
        return "sysctl %s=%s" % (self.key, self.value)


@dataclass
class Run:
    cmd: list
    undo: list = None
    ignore_fail: bool = False

    def summary(self):
        return " ".join(self.cmd)


@dataclass
class Service:
    name: str
    enable: bool = True
    state: str = "started"     # started | restarted | stopped | keep

    def summary(self):
        return "service %s: %s%s" % (self.name, self.state, " + enable" if self.enable else "")


@dataclass
class Install:
    packages: list

    def summary(self):
        return "install %s" % " ".join(self.packages)


@dataclass
class Plan:
    module: str
    actions: list = field(default_factory=list)
    notes: list = field(default_factory=list)      # (i18n key, params)
    warnings: list = field(default_factory=list)   # (i18n key, params)
    skip: tuple = None                             # (i18n key, params) when nothing to do

    @property
    def empty(self):
        return not self.actions


@dataclass
class Finding:
    module: str
    status: str            # ok | todo | na | info
    key: str
    params: dict = field(default_factory=dict)
    weight: int = 0
