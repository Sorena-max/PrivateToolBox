"""A tiny local service so a PrivateChecker bot can run PrivateToolBox.

It listens on a Unix socket that only root and the `privatetoolbox` group can
open. It accepts one JSON object per connection and only a short list of
commands. Every value is checked against a fixed list or pattern before it is
turned into command line arguments, and the command runs without a shell, so a
request can never inject its own options or commands.
"""

import json
import os
import re
import subprocess
import threading

from . import __version__, safety
from .engine import Engine
from .modules import BY_ID, PROFILES
from .modules.firewall import normalize_port
from .system import System

SOCKET = "/run/privatetoolbox/agent.sock"
GROUP = "privatetoolbox"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
RUN_ID = re.compile(r"^(last|\d{8}-\d{6}(-\d+)?)$")
PORT_ONLY = re.compile(r"^\d{1,5}(/(tcp|udp))?$")
DNS_CHOICES = {"auto", "keep", "cloudflare", "google", "quad9", "opendns", "adguard"}
TIMEOUTS = {"scan": 120, "plan": 180, "apply": 900, "undo": 300, "confirm": 30,
            "history": 30, "verify": 240, "dns-test": 120}
MAX_OUTPUT = 20000
LOCK = threading.Lock()


class BadRequest(Exception):
    pass


def _bool(value, name):
    if not isinstance(value, bool):
        raise BadRequest("%s must be true or false" % name)
    return value


def _int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise BadRequest("%s must be a number from %d to %d" % (name, low, high))
    return value


def _list(value, name, limit):
    if not isinstance(value, list) or len(value) > limit or not all(isinstance(v, str) for v in value):
        raise BadRequest("%s must be a short list of strings" % name)
    return value


def option_args(opts):
    """Turn a dict of options into a checked list of command line arguments."""
    if not isinstance(opts, dict):
        raise BadRequest("opts must be an object")
    args = []
    for key, value in opts.items():
        if key == "dns":
            if value not in DNS_CHOICES:
                raise BadRequest("unknown dns choice")
            args += ["--dns", value]
        elif key == "ssh_keys_only":
            if _bool(value, key):
                args.append("--ssh-keys-only")
        elif key == "ssh_port":
            args += ["--ssh-port", str(_int(value, key, 1, 65535))]
        elif key == "open":
            for spec in _list(value, key, 20):
                if normalize_port(spec) is None:
                    raise BadRequest("invalid port %r" % spec)
                args += ["--open", spec]
        elif key == "exclude":
            for spec in _list(value, key, 20):
                if not PORT_ONLY.match(spec):
                    raise BadRequest("invalid port %r" % spec)
                args += ["--exclude", spec]
        elif key == "no_discover":
            if _bool(value, key):
                args.append("--no-discover")
        elif key == "abuse_profile":
            if value not in ("minimal", "aggressive"):
                raise BadRequest("unknown abuse profile")
            args += ["--abuse-profile", value]
        elif key == "block_smtp":
            if _bool(value, key):
                args.append("--block-smtp")
        elif key == "swap_mb":
            args += ["--swap-mb", str(_int(value, key, 128, 8192))]
        elif key == "forward_accept":
            if _bool(value, key):
                args.append("--forward-accept")
        else:
            raise BadRequest("unknown option %r" % key)
    return args


def build_argv(request):
    """The privatetoolbox arguments for a request, or BadRequest."""
    cmd = request.get("cmd")
    lang = request.get("lang", "en")
    if lang not in ("en", "fa"):
        raise BadRequest("unknown language")
    base = ["--lang", lang]
    if cmd in ("scan", "history", "dns-test", "confirm"):
        return base + [cmd]
    if cmd == "verify":
        argv = base + ["verify", "--no-notify"]
        if request.get("iran") is True:
            argv.append("--iran")
        return argv
    if cmd == "undo":
        run_id = request.get("run", "last")
        if not isinstance(run_id, str) or not RUN_ID.match(run_id):
            raise BadRequest("invalid run id")
        return base + ["undo", run_id]
    if cmd in ("plan", "apply"):
        argv = base + [cmd]
        profile, modules = request.get("profile"), request.get("modules")
        if profile is not None:
            if profile not in PROFILES:
                raise BadRequest("unknown profile")
            argv += ["--profile", profile]
        elif modules is not None:
            for name in _list(modules, "modules", 20):
                if name not in BY_ID:
                    raise BadRequest("unknown module")
            argv += modules
        else:
            raise BadRequest("give a profile or modules")
        argv += option_args(request.get("opts") or {})
        if cmd == "apply":
            seconds = _int(request.get("rollback", 180), "rollback", 60, 600)
            argv += ["--yes", "--hold", "--no-notify", "--rollback", str(seconds)]
        return argv
    raise BadRequest("unknown command")


def clean(text):
    text = ANSI.sub("", text or "").replace("\r", "")
    return text[-MAX_OUTPUT:]


def run_process(argv, timeout):
    env = dict(os.environ, NO_COLOR="1", TERM="dumb", LC_ALL="C.UTF-8")
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              timeout=timeout, universal_newlines=True, env=env)
        return proc.returncode, proc.stdout
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except OSError as exc:
        return 127, str(exc)


def execute(request, runner=run_process, system=None):
    """Handle one request and return the reply dictionary."""
    system = system or System()
    if not isinstance(request, dict):
        return {"ok": False, "error": "bad request"}
    cmd = request.get("cmd")
    if cmd == "ping":
        return {"ok": True, "version": __version__}
    if cmd == "status":
        return {"ok": True, "pending": safety.pending_run(system, Engine(system))}
    try:
        argv = build_argv(request)
    except BadRequest as exc:
        return {"ok": False, "error": str(exc)}
    if not LOCK.acquire(blocking=False):
        return {"ok": False, "error": "busy"}
    try:
        code, output = runner([safety.executable()] + argv, TIMEOUTS[cmd])
    finally:
        LOCK.release()
    reply = {"ok": code == 0, "code": code, "output": clean(output)}
    if cmd in ("apply", "confirm", "undo"):
        reply["pending"] = safety.pending_run(system, Engine(system))
    return reply


def serve(path=None):
    import grp
    import socketserver

    path = path or os.environ.get("PRIVATETOOLBOX_SOCKET", SOCKET)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            try:
                request = json.loads(self.rfile.readline(65536).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                request = None
            reply = execute(request)
            self.wfile.write((json.dumps(reply) + "\n").encode("utf-8"))

    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.remove(path)
    server = socketserver.ThreadingUnixStreamServer(path, Handler)
    try:
        os.chown(path, 0, grp.getgrnam(GROUP).gr_gid)
        os.chmod(path, 0o660)
    except KeyError:
        os.chmod(path, 0o600)       # no group yet: root only
    try:
        server.serve_forever()
    finally:
        server.server_close()
