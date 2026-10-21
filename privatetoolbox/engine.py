"""Applies actions and keeps a journal so every run can be undone."""

import base64
import json
import os
import posixpath

from . import actions as act

STATE_DIR_DEFAULT = "/var/lib/privatetoolbox"


class ApplyError(Exception):
    pass


def state_dir():
    return os.environ.get("PRIVATETOOLBOX_HOME", STATE_DIR_DEFAULT)


def install_command(system, packages):
    if system.which("apt-get"):
        return ["apt-get", "install", "-y", "-qq"] + list(packages)
    if system.which("dnf"):
        return ["dnf", "install", "-y", "-q"] + list(packages)
    if system.which("yum"):
        return ["yum", "install", "-y", "-q"] + list(packages)
    return None


class Engine:
    def __init__(self, system, home=None):
        self.system = system
        self.home = home or state_dir()

    # journal files ----------------------------------------------------
    def _path(self, run_id):
        return posixpath.join(self.home, "runs", "%s.json" % run_id)

    def _save(self, journal):
        self.system.write(self._path(journal["id"]),
                          json.dumps(journal, indent=1), mode=0o600)

    def load(self, run_id):
        if run_id == "last":
            ids = self.run_ids()
            if not ids:
                return None
            run_id = ids[-1]
        text = self.system.read(self._path(run_id))
        return json.loads(text) if text else None

    def run_ids(self):
        names = self.system.listdir(posixpath.join(self.home, "runs"))
        return [n[:-5] for n in names if n.endswith(".json")]

    def new_run_id(self):
        import time
        base = time.strftime("%Y%m%d-%H%M%S", time.localtime(self.system.now()))
        run_id, n = base, 1
        while run_id in self.run_ids():
            n += 1
            run_id = "%s-%d" % (base, n)
        return run_id

    # apply ------------------------------------------------------------
    def apply(self, plans, run_id=None, on_step=None):
        """Apply every action of every plan. On any failure, undo what was done."""
        run_id = run_id or self.new_run_id()
        journal = {"id": run_id, "time": self.system.now(),
                   "modules": [p.module for p in plans], "status": "applying",
                   "entries": []}
        self._save(journal)
        try:
            for plan in plans:
                for action in plan.actions:
                    journal["entries"].append(self._record(action))
                    self._save(journal)
                    if on_step:
                        on_step(plan.module, action)
                    self._execute(action)
        except Exception as exc:
            self._rollback(journal)
            journal["status"] = "failed"
            self._save(journal)
            raise ApplyError(str(exc))
        journal["status"] = "applied"
        self._save(journal)
        return run_id

    def _b64(self, data):
        return None if data is None else base64.b64encode(data).decode("ascii")

    def _record(self, action):
        sysm = self.system
        if isinstance(action, act.WriteFile):
            return {"type": "file", "path": action.path,
                    "old": self._b64(sysm.read_bytes(action.path)),
                    "mode": sysm.mode(action.path), "undo_after": action.undo_after}
        if isinstance(action, act.Snapshot):
            return {"type": "snapshot", "undo_after": action.undo_after,
                    "files": {p: [self._b64(sysm.read_bytes(p)), sysm.mode(p)]
                              for p in action.paths}}
        if isinstance(action, act.Sysctl):
            return {"type": "sysctl", "key": action.key, "old": sysm.sysctl_get(action.key)}
        if isinstance(action, act.Run):
            return {"type": "run", "undo": action.undo}
        if isinstance(action, act.Service):
            _, enabled = sysm.run(["systemctl", "is-enabled", action.name])
            _, active = sysm.run(["systemctl", "is-active", action.name])
            return {"type": "service", "name": action.name,
                    "was_enabled": enabled.strip() == "enabled",
                    "was_active": active.strip() == "active"}
        if isinstance(action, act.Install):
            return {"type": "install", "packages": action.packages}
        raise ApplyError("unknown action %r" % (action,))

    def _must(self, cmd, timeout=300):
        code, out = self.system.run(cmd, timeout=timeout)
        if code != 0:
            raise ApplyError("%s failed: %s" % (" ".join(cmd), out.strip()[-300:]))
        return out

    def _execute(self, action):
        sysm = self.system
        if isinstance(action, act.WriteFile):
            sysm.write(action.path, action.content, action.mode)
            if action.validate:
                self._must(action.validate)
            if action.after:
                self._must(action.after)
        elif isinstance(action, act.Snapshot):
            pass
        elif isinstance(action, act.Sysctl):
            self._must(["sysctl", "-w", "%s=%s" % (action.key, action.value)])
        elif isinstance(action, act.Run):
            code, out = sysm.run(action.cmd, timeout=300)
            if code != 0 and not action.ignore_fail:
                raise ApplyError("%s failed: %s" % (" ".join(action.cmd), out.strip()[-300:]))
        elif isinstance(action, act.Service):
            if action.enable:
                sysm.run(["systemctl", "enable", action.name])
            if action.state == "started":
                self._must(["systemctl", "start", action.name])
            elif action.state == "restarted":
                self._must(["systemctl", "restart", action.name])
            elif action.state == "stopped":
                self._must(["systemctl", "stop", action.name])
        elif isinstance(action, act.Install):
            cmd = install_command(sysm, action.packages)
            if cmd is None:
                raise ApplyError("no supported package manager to install %s"
                                 % " ".join(action.packages))
            if sysm.which("apt-get"):
                sysm.run(["apt-get", "update", "-qq"], timeout=300)
            self._must(cmd, timeout=900)

    # undo -------------------------------------------------------------
    def undo(self, run_id):
        journal = self.load(run_id)
        if journal is None:
            raise ApplyError("no such run: %s" % run_id)
        if journal["status"] == "undone":
            raise ApplyError("run %s was already undone" % journal["id"])
        messages = self._rollback(journal)
        journal["status"] = "undone"
        self._save(journal)
        return journal["id"], messages

    def _rollback(self, journal):
        sysm = self.system
        messages = []
        for entry in reversed(journal["entries"]):
            kind = entry["type"]
            try:
                if kind == "file":
                    self._restore(entry["path"], entry["old"], entry.get("mode"))
                    messages.append("restored %s" % entry["path"])
                    if entry.get("undo_after"):
                        sysm.run(entry["undo_after"])
                elif kind == "snapshot":
                    for path, (old, mode) in entry["files"].items():
                        self._restore(path, old, mode)
                    messages.append("restored %d file(s)" % len(entry["files"]))
                    if entry.get("undo_after"):
                        sysm.run(entry["undo_after"])
                elif kind == "sysctl" and entry["old"] is not None:
                    sysm.run(["sysctl", "-w", "%s=%s" % (entry["key"], entry["old"])])
                    messages.append("sysctl %s back to %s" % (entry["key"], entry["old"]))
                elif kind == "run" and entry.get("undo"):
                    sysm.run(entry["undo"])
                    messages.append("ran %s" % " ".join(entry["undo"]))
                elif kind == "service":
                    name = entry["name"]
                    if not entry["was_enabled"]:
                        sysm.run(["systemctl", "disable", name])
                    if entry["was_active"]:
                        sysm.run(["systemctl", "restart", name])
                    else:
                        sysm.run(["systemctl", "stop", name])
                    messages.append("service %s back to its old state" % name)
            except OSError as exc:
                messages.append("could not undo %s: %s" % (kind, exc))
        return messages

    def _restore(self, path, old_b64, mode=None):
        if old_b64 is None:
            self.system.remove(path)
        else:
            self.system.write(path, base64.b64decode(old_b64), mode or 0o644)
