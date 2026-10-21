"""Terminal output: colours when it is a real terminal, plain text otherwise."""

import os
import sys

from .i18n import t

PRIVATE = [
    "██████╗ ██████╗ ██╗██╗   ██╗ █████╗ ████████╗███████╗",
    "██╔══██╗██╔══██╗██║██║   ██║██╔══██╗╚══██╔══╝██╔════╝",
    "██████╔╝██████╔╝██║██║   ██║███████║   ██║   █████╗  ",
    "██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║   ██║   ██╔══╝  ",
    "██║     ██║  ██║██║ ╚████╔╝ ██║  ██║   ██║   ███████╗",
    "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝   ╚═╝   ╚══════╝",
]
TOOLBOX = [
    "████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗",
    "╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝",
    "   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝ ",
    "   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗ ",
    "   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗",
    "   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝",
]
SHADES = [51, 45, 39, 33, 27, 21]


class UI:
    def __init__(self, stream=None, color=None, utf8=None):
        self.out = stream or sys.stdout
        tty = hasattr(self.out, "isatty") and self.out.isatty()
        if color is None:
            color = tty and not os.environ.get("NO_COLOR") and os.environ.get("TERM", "dumb") != "dumb"
        if utf8 is None:
            locale = os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE") or os.environ.get("LANG", "")
            utf8 = "utf-8" in locale.lower() or "utf8" in locale.lower()
        self.color = color
        self.utf8 = utf8
        self.sym = {"ok": "✔", "bad": "✖", "warn": "!", "info": "•"} if utf8 else \
            {"ok": "[ok]", "bad": "[x]", "warn": "[!]", "info": "-"}

    def _c(self, code, text):
        return "\033[%sm%s\033[0m" % (code, text) if self.color else text

    def p(self, text=""):
        print(text, file=self.out)

    def heading(self, text):
        self.p("")
        self.p(self._c("1;36", text))
        self.p(self._c("2", "-" * min(60, max(20, len(text)))))

    def ok(self, text):
        self.p("  %s %s" % (self._c("1;32", self.sym["ok"]), text))

    def bad(self, text):
        self.p("  %s %s" % (self._c("1;31", self.sym["bad"]), text))

    def warn(self, text):
        self.p("  %s %s" % (self._c("1;33", self.sym["warn"]), text))

    def info(self, text):
        self.p("  %s %s" % (self._c("2", self.sym["info"]), text))

    def dim(self, text):
        return self._c("2", text)

    def bold(self, text):
        return self._c("1", text)

    def bar(self, score, width=24):
        filled = int(round(score / 100.0 * width))
        full, empty = ("█", "░") if self.utf8 else ("#", ".")
        color = "1;32" if score >= 80 else "1;33" if score >= 50 else "1;31"
        return "%s %s" % (self._c(color, full * filled + empty * (width - filled)), "%d/100" % score)

    def banner(self, lang, version):
        if self.utf8 and self.color:
            for index, line in enumerate(PRIVATE + TOOLBOX):
                shade = SHADES[index % 6]
                self.p("  \033[38;5;%dm%s\033[0m" % (shade, line))
        else:
            self.p("  == PRIVATE TOOLBOX ==")
        self.p("")
        self.p("  %s  %s" % (self.bold("PrivateToolBox (Private Tool)"), self.dim("v%s" % version)))
        self.p("  %s" % t(lang, "tagline"))
        self.p("  GitHub: Sorena-max")
        self.p("  %s" % self._c("1;33", t(lang, "free_notice")))
