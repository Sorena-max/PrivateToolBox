"""Everything that touches the machine goes through System, so tests can fake it."""

import os
import shutil
import subprocess
import time


class System:
    def read(self, path):
        data = self.read_bytes(path)
        return None if data is None else data.decode("utf-8", "replace")

    def read_bytes(self, path):
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError:
            return None

    def write(self, path, content, mode=0o644):
        if isinstance(content, str):
            content = content.encode("utf-8")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = "%s.ptb-tmp" % path
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, path)

    def mode(self, path):
        try:
            return os.stat(path).st_mode & 0o777
        except OSError:
            return None

    def remove(self, path):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def exists(self, path):
        return os.path.exists(path)

    def islink(self, path):
        return os.path.islink(path)

    def listdir(self, path):
        try:
            return sorted(os.listdir(path))
        except OSError:
            return []

    def run(self, cmd, timeout=60):
        """Run a command. Returns (code, output); code is None if it could not start."""
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=timeout, universal_newlines=True,
                                  env=dict(os.environ, DEBIAN_FRONTEND="noninteractive"))
            return proc.returncode, proc.stdout
        except subprocess.TimeoutExpired:
            return None, "timeout"
        except OSError as exc:
            return None, str(exc)

    def which(self, name):
        return shutil.which(name)

    def is_root(self):
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def env(self, name, default=""):
        return os.environ.get(name, default)

    def sysctl_get(self, key):
        text = self.read("/proc/sys/" + key.replace(".", "/"))
        return None if text is None else text.strip()

    def now(self):
        return time.time()

    def free_bytes(self, path):
        try:
            st = os.statvfs(path)
            return st.f_bavail * st.f_frsize
        except (OSError, AttributeError):
            return 0
