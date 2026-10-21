"""Optional: report results through a PrivateChecker bot on the same server."""

import json
import os
import posixpath
import urllib.request


def checker_config(system):
    home = os.environ.get("PRIVATECHECKER_HOME", "/var/lib/privatechecker")
    text = system.read(posixpath.join(home, "config.json"))
    try:
        data = json.loads(text) if text else None
    except ValueError:
        return None
    if data and data.get("token") and data.get("owner_id"):
        return data
    return None


def send(system, text, post=None):
    """Send `text` to the PrivateChecker owner. Returns True on success."""
    cfg = checker_config(system)
    if not cfg:
        return False
    base = str(cfg.get("api_base") or "https://api.telegram.org").rstrip("/")
    url = "%s/bot%s/sendMessage" % (base, cfg["token"])
    body = json.dumps({"chat_id": cfg["owner_id"], "text": text}).encode("utf-8")
    post = post or _post
    try:
        return bool(post(url, body))
    except OSError:
        return False


def _post(url, body):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8")).get("ok", False)
