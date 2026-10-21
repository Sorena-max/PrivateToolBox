"""Can people in Iran reach this server? Asks the check-host.net probes inside Iran."""

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

API = "https://check-host.net"
MAX_NODES = 3


def _get(path):
    req = urllib.request.Request(API + path, headers={
        "Accept": "application/json", "User-Agent": "PrivateToolBox/%s" % __version__})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise OSError(str(exc))
    if isinstance(data, dict) and data.get("error") and "request_id" not in data:
        raise OSError(str(data["error"]))
    return data


def iran_nodes(payload):
    found = []
    for name, info in sorted(((payload or {}).get("nodes") or {}).items()):
        loc = (info or {}).get("location") or []
        if loc and str(loc[0]).lower() == "ir":
            found.append(name)
    return found


def count_ok(rows):
    """Number of successful pings in one node's answer, or None while pending."""
    if not rows or rows == [None]:
        return None
    first = rows[0] if isinstance(rows, list) else None
    if first is None:
        return None
    if not isinstance(first, list):
        return 0
    return sum(1 for r in first if isinstance(r, list) and r and r[0] == "OK")


def public_ip(get=None):
    get = get or (lambda: urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip())
    try:
        return get()
    except OSError:
        return None


def reach(host, get=_get, sleep=time.sleep):
    """Return (reachable_nodes, total_nodes), or None if check-host.net is unavailable."""
    try:
        names = iran_nodes(get("/nodes/hosts"))[:MAX_NODES]
        if not names:
            return None
        query = urllib.parse.urlencode([("host", host)] + [("node", n) for n in names])
        started = None
        for _ in range(3):
            try:
                started = get("/check-ping?" + query)
                break
            except OSError as exc:
                if "limit" not in str(exc):
                    return None
                sleep(20)
        if not started:
            return None
        results = {}
        for _ in range(10):
            sleep(3)
            raw = get("/check-result/%s" % started["request_id"])
            results = {n: count_ok(raw.get(n)) for n in names}
            if all(v is not None for v in results.values()):
                break
        answered = [v for v in results.values() if v is not None]
        return sum(1 for v in answered if v > 0), len(answered)
    except OSError:
        return None
