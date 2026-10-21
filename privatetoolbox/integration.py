"""Working with PrivateChecker on the same server: detect it and write its reports."""

import socket

from . import notify
from .i18n import t


def checker_active(system):
    """True when a PrivateChecker bot is configured and its service is running."""
    if notify.checker_config(system) is None:
        return False
    _, out = system.run(["systemctl", "is-active", "privatechecker"], timeout=10)
    return out.strip() == "active"


def checker_language(system):
    lang = (notify.checker_config(system) or {}).get("language")
    return lang if lang in ("fa", "en") else "en"


def _check_lines(lang, results):
    lines = []
    for module_id, ok, key, params in results:
        lines.append("%s %s: %s" % ("✅" if ok else "❌", t(lang, "mod_" + module_id),
                                    t(lang, key, **params)))
    return lines


def apply_report(lang, run_id, modules, before, after, results, held, code):
    """Plain text (no secrets) summarising an apply run."""
    good = code == 0 and all(ok for _, ok, _, _ in results)
    lines = ["🧰 PrivateToolBox",
             t(lang, "n_host", host=socket.gethostname()),
             ("✅ " if good else "⚠️ ") + t(lang, "n_applied" if good else "n_check"),
             t(lang, "n_run", id=run_id, modules=", ".join(t(lang, "mod_" + m) for m in modules)),
             t(lang, "n_score", before=before, after=after)]
    lines += _check_lines(lang, results)
    if held:
        lines.append("⏳ " + t(lang, "n_pending"))
    return "\n".join(lines)


def scan_report(lang, findings, value):
    """Plain text summary of a scan: the score, then what is fine and what can be improved."""
    lines = ["🧰 PrivateToolBox", t(lang, "n_host", host=socket.gethostname()),
             t(lang, "n_scan"), t(lang, "n_score_now", value=value)]
    for finding in findings:
        if finding.status in ("ok", "todo"):
            lines.append("%s %s: %s" % ("✅" if finding.status == "ok" else "❌",
                                        t(lang, "mod_" + finding.module),
                                        t(lang, finding.key, **finding.params)))
    return "\n".join(lines)


def verify_report(lang, results):
    good = all(ok for _, ok, _, _ in results)
    lines = ["🧰 PrivateToolBox", t(lang, "n_host", host=socket.gethostname()),
             ("✅ " + t(lang, "n_all_ok")) if good else ("⚠️ " + t(lang, "n_check")),
             t(lang, "n_verify_title")]
    return "\n".join(lines + _check_lines(lang, results))
