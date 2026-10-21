"""Command line: scan, plan, apply, undo, confirm, history, verify, dns-test, menu."""

import argparse
import select
import sys
import time

from . import __version__, bridge, integration, iran, notify, safety
from . import modules as mods
from .actions import Plan
from .context import Context, Options
from .engine import ApplyError, Engine
from .i18n import t
from .modules.dns import benchmark
from .system import System
from .ui import UI


def score(findings):
    good = sum(f.weight for f in findings if f.status == "ok")
    total = good + sum(f.weight for f in findings if f.status == "todo")
    return 100 if total == 0 else int(round(good * 100.0 / total))


def split_list(values):
    out = []
    for value in values or []:
        out += [v for v in value.replace(",", " ").split() if v]
    return out


def make_parser():
    p = argparse.ArgumentParser(prog="privatetoolbox",
                                description="Safe hardening and tuning for a Linux server")
    # Terminals draw Persian badly, so output is English. Telegram reports are in
    # your PrivateChecker language; --lang only exists for the Telegram bridge.
    p.add_argument("--lang", choices=["en", "fa"], help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="command")
    sub.add_parser("agent", help=argparse.SUPPRESS)
    integrate = sub.add_parser("integrate", help="add or remove the PrivateToolBox button in your PrivateChecker bot")
    integrate.add_argument("-y", "--yes", action="store_true")
    integrate.add_argument("--remove", action="store_true")
    scan = sub.add_parser("scan", help="read-only audit with a score")
    scan.add_argument("--notify", action="store_true", help="send the result to PrivateChecker")
    scan.add_argument("--no-notify", action="store_true", help="do not offer to send the result")
    sub.add_parser("menu", help="interactive menu")
    sub.add_parser("version")
    sub.add_parser("history", help="list past runs")
    sub.add_parser("confirm", help="keep the last change (cancels the automatic rollback)")
    sub.add_parser("dns-test", help="measure public DNS resolvers from this server")
    undo = sub.add_parser("undo", help="undo a run")
    undo.add_argument("run", nargs="?", default="last")
    undo.add_argument("--quiet", action="store_true")
    verify = sub.add_parser("verify", help="check that the applied settings work")
    verify.add_argument("--iran", action="store_true", help="also check reachability from Iran")
    verify.add_argument("--notify", action="store_true", help="send the result to PrivateChecker")
    verify.add_argument("--no-notify", action="store_true", help="do not offer to send the result")

    for name, help_text in (("plan", "show what would change"), ("apply", "make the changes")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("modules", nargs="*", help="modules: " + ", ".join(m.id for m in mods.ALL))
        sp.add_argument("--profile", choices=sorted(mods.PROFILES))
        sp.add_argument("--dns", default="auto", help="auto, keep, or %s" % "|".join(
            ["cloudflare", "google", "quad9", "opendns", "adguard"]))
        sp.add_argument("--ssh-port", type=int, help="also listen on this SSH port")
        sp.add_argument("--ssh-keys-only", action="store_true", help="turn off password login")
        sp.add_argument("--open", action="append", help='extra ports, e.g. "443 51820/udp 1000:2000/tcp"')
        sp.add_argument("--exclude", action="append", help="listening ports to leave closed")
        sp.add_argument("--no-discover", action="store_true", help="do not open listening ports")
        sp.add_argument("--abuse-profile", choices=["minimal", "aggressive"], default="minimal")
        sp.add_argument("--block-smtp", action="store_true")
        sp.add_argument("--swap-mb", type=int, default=1024)
        sp.add_argument("--forward-accept", action="store_true")
        if name == "apply":
            sp.add_argument("-y", "--yes", action="store_true", help="do not ask")
            sp.add_argument("--rollback", type=int, default=safety.DEFAULT_SECONDS, metavar="SECONDS")
            sp.add_argument("--no-rollback", action="store_true")
            sp.add_argument("--hold", action="store_true",
                            help="with --yes: never confirm by itself, wait for 'privatetoolbox confirm'")
            sp.add_argument("--notify", action="store_true", help="send the report to PrivateChecker")
            sp.add_argument("--no-notify", action="store_true", help="do not offer to send the report")
            sp.add_argument("--iran", action="store_true")
    return p


def options_from(args):
    return Options(
        ssh_port=getattr(args, "ssh_port", None),
        ssh_keys_only=getattr(args, "ssh_keys_only", False),
        extra_ports=split_list(getattr(args, "open", None)),
        exclude_ports=split_list(getattr(args, "exclude", None)),
        discover=not getattr(args, "no_discover", False),
        dns=getattr(args, "dns", "auto"),
        abuse_profile=getattr(args, "abuse_profile", "minimal"),
        abuse_block_smtp=getattr(args, "block_smtp", False),
        swap_mb=getattr(args, "swap_mb", 1024),
        forward_accept=True if getattr(args, "forward_accept", False) else None,
    )


class App:
    def __init__(self, system=None, ui=None, input_fn=input, ask_keep=None, dns_benchmark=None):
        self.system = system or System()
        self.ui = ui or UI()
        self.input_fn = input_fn
        self.ask_keep = ask_keep or self._ask_keep
        self.dns_benchmark = dns_benchmark
        self.engine = Engine(self.system)
        self.lang = "en"
        self.interactive = sys.stdin.isatty()
        self.findings = []

    # helpers ----------------------------------------------------------
    def tr(self, key, **params):
        return t(self.lang, key, **params)

    def title(self, module_id):
        return self.tr("mod_" + module_id)

    def resolve_lang(self, args):
        if getattr(args, "lang", None):
            return args.lang
        env = self.system.env("PRIVATETOOLBOX_LANG")
        return env if env in ("fa", "en") else "en"

    def context(self, args=None):
        opts = options_from(args) if args is not None else Options()
        return Context(self.system, opts, dns_benchmark=self.dns_benchmark)

    def need_root(self):
        if not self.system.is_root():
            self.ui.bad(self.tr("need_root"))
            return False
        return True

    def os_warning(self, ctx):
        if not ctx.tested_os:
            self.ui.warn(self.tr("untested_os", os=ctx.os_name))

    def _ask_keep(self, seconds):
        self.ui.out.write(self.tr("ask_keep"))
        self.ui.out.flush()
        if sys.stdin.isatty():
            ready, _, _ = select.select([sys.stdin], [], [], seconds)
            return sys.stdin.readline().strip() if ready else ""
        return self.input_fn("")

    # scan -------------------------------------------------------------
    def scan(self, ctx=None):
        ctx = ctx or self.context()
        self.ui.heading(self.tr("scan_title"))
        self.os_warning(ctx)
        findings = []
        for module in mods.ALL:
            finding = module.scan(ctx)
            findings.append(finding)
            text = "%s: %s" % (self.title(finding.module), self.tr(finding.key, **finding.params))
            if finding.status == "ok":
                self.ui.ok(text)
            elif finding.status == "todo":
                self.ui.bad(text)
            elif finding.status == "info":
                self.ui.info(text)
            else:
                self.ui.info(self.ui.dim(text))
        value = score(findings)
        self.ui.p("")
        self.ui.p("  %s  %s" % (self.tr("score"), self.ui.bar(value)))
        self.findings = findings
        return value

    def scan_cmd(self, args):
        value = self.scan()
        self.send_to_checker(args, lambda lang: integration.scan_report(lang, self.findings, value))
        return 0

    # plan / apply -----------------------------------------------------
    def pick_modules(self, args):
        if args.modules:
            unknown = [m for m in args.modules if m not in mods.BY_ID]
            if unknown:
                for name in unknown:
                    self.ui.bad(self.tr("unknown_module", name=name))
                return None
            return mods.select(args.modules)
        return mods.select(mods.PROFILES[args.profile or "recommended"])

    def build_plans(self, ctx, selected):
        plans = []
        for module in selected:
            try:
                plans.append(module.plan(ctx))
            except Exception as exc:
                plans.append(Plan(module.id, skip=("plan_error", {"error": str(exc)})))
        return plans

    def show_plans(self, plans):
        self.ui.heading(self.tr("plan_title"))
        for plan in plans:
            name = self.ui.bold(self.title(plan.module))
            if plan.skip:
                self.ui.info("%s: %s" % (name, self.tr(plan.skip[0], **plan.skip[1])))
                continue
            self.ui.ok(name)
            for key, params in plan.notes:
                self.ui.p("      %s" % self.tr(key, **params))
            for key, params in plan.warnings:
                self.ui.warn("    " + self.tr(key, **params))
            for action in plan.actions:
                self.ui.p("      %s" % self.ui.dim("- " + action.summary()))

    def plan_cmd(self, args):
        selected = self.pick_modules(args)
        if selected is None:
            return 2
        ctx = self.context(args)
        self.os_warning(ctx)
        plans = self.build_plans(ctx, selected)
        self.show_plans(plans)
        if all(p.empty for p in plans):
            self.ui.p("")
            self.ui.ok(self.tr("nothing"))
        return 0

    def verify_results(self, ctx, module_ids):
        results = []
        for module in mods.select(module_ids):
            for ok, key, params in module.verify(ctx):
                results.append((module.id, ok, key, params))
        return results

    def show_checks(self, results):
        self.ui.heading(self.tr("verify_title"))
        for module_id, ok, key, params in results:
            line = "%s: %s" % (self.title(module_id), self.tr(key, **params))
            (self.ui.ok if ok else self.ui.bad)(line)

    def apply_cmd(self, args):
        if not self.need_root():
            return 2
        selected = self.pick_modules(args)
        if selected is None:
            return 2
        ctx = self.context(args)
        self.os_warning(ctx)
        plans = self.build_plans(ctx, selected)
        self.show_plans(plans)
        active = [p for p in plans if not p.empty]
        if not active:
            self.ui.p("")
            self.ui.ok(self.tr("nothing"))
            return 0
        if not args.yes and self.input_fn(self.tr("ask_apply")).strip().lower() not in ("y", "yes"):
            self.ui.p(self.tr("cancelled"))
            return 1

        before = score([m.scan(ctx) for m in mods.ALL])
        run_id = self.engine.new_run_id()
        modules = [p.module for p in active]
        armed = False
        if safety.needs_rollback(modules) and not args.no_rollback:
            armed = safety.arm(self.system, run_id, args.rollback)
            if not armed:
                self.ui.bad(self.tr("rollback_failed"))
                return 2
            self.ui.warn(self.tr("rollback_armed", seconds=args.rollback))

        self.ui.heading(self.tr("applying"))
        try:
            self.engine.apply(active, run_id, on_step=lambda mod, act: self.ui.info(
                "%s: %s" % (self.title(mod), act.summary())))
        except ApplyError as exc:
            if armed:
                safety.confirm(self.system, run_id)
            self.ui.bad(self.tr("apply_failed", error=exc))
            return 1

        results = self.verify_results(ctx, modules)
        self.show_checks(results)
        all_ok = all(ok for _, ok, _, _ in results)
        after = score([m.scan(Context(self.system, ctx.opts, ctx.dns_benchmark)) for m in mods.ALL])
        self.ui.p("")
        self.ui.p("  %s  %s" % (self.tr("score"), self.ui.bar(before)))
        self.ui.p("  %s  %s" % (self.tr("score_after"), self.ui.bar(after)))
        self.ui.ok(self.tr("applied_summary", n=sum(len(p.actions) for p in active)))

        code = 0
        if armed:
            code = self.finish_rollback(run_id, args, all_ok)
        if args.iran:
            self.show_iran()
        held = armed and args.yes and args.hold
        self.send_to_checker(args, lambda lang: integration.apply_report(
            lang, run_id, modules, before, after, results, held, code))
        return code

    def finish_rollback(self, run_id, args, all_ok):
        self.ui.p("")
        if args.yes and args.hold:
            self.ui.warn(self.tr("pending_hold", seconds=args.rollback))
            return 0
        if args.yes:
            if all_ok:
                safety.confirm(self.system, run_id)
                self.ui.ok(self.tr("auto_kept"))
                return 0
            self.ui.warn(self.tr("rolled_back_pending"))
            return 3
        self.ui.warn(self.tr("rollback_hint"))
        answer = self.ask_keep(args.rollback)
        if answer.strip().lower() in ("yes", "y"):
            safety.confirm(self.system, run_id)
            self.ui.ok(self.tr("kept"))
            return 0
        self.ui.warn(self.tr("rolled_back_pending"))
        return 3

    def send_to_checker(self, args, build_text):
        """Offer to send a report to the PrivateChecker bot on this server.

        With --notify it just sends. Without it, a person at a terminal is asked
        first, and only if PrivateChecker is really running. Scripts (--yes) are
        never asked.
        """
        if getattr(args, "no_notify", False):
            return
        if not getattr(args, "notify", False):
            if getattr(args, "yes", False) or not self.interactive:
                return
            if not integration.checker_active(self.system):
                return
            answer = self.input_fn(self.tr("ask_send_checker"))
            if answer.strip().lower() not in ("y", "yes"):
                return
        elif notify.checker_config(self.system) is None:
            self.ui.warn(self.tr("checker_missing"))
            return
        lang = integration.checker_language(self.system)
        sent = notify.send(self.system, build_text(lang))
        (self.ui.ok if sent else self.ui.warn)(self.tr("sent_checker" if sent else "send_failed"))

    # other commands ---------------------------------------------------
    def undo_cmd(self, args):
        if not self.need_root():
            return 2
        try:
            run_id, messages = self.engine.undo(args.run)
        except ApplyError as exc:
            if not args.quiet:
                self.ui.bad(str(exc))
            return 1
        safety.confirm(self.system, run_id)     # drop a rollback timer that is still waiting
        if not args.quiet:
            for message in messages:
                self.ui.info(message)
            self.ui.ok(self.tr("undo_done", id=run_id))
        return 0

    def confirm_cmd(self):
        if not self.need_root():
            return 2
        run_id = safety.pending_run(self.system, self.engine)
        if not run_id:
            self.ui.warn(self.tr("confirm_none"))
            return 1
        safety.confirm(self.system, run_id)
        self.ui.ok(self.tr("confirm_ok"))
        return 0

    def history_cmd(self):
        ids = self.engine.run_ids()
        if not ids:
            self.ui.info(self.tr("history_none"))
            return 0
        for run_id in ids:
            journal = self.engine.load(run_id)
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(journal["time"]))
            self.ui.p("  %s  %-9s %s" % (when, journal["status"], ", ".join(journal["modules"])))
            self.ui.p("      id: %s" % run_id)
        return 0

    def verify_cmd(self, args):
        ctx = self.context()
        # only check what is actually set up on this server
        active = [m.id for m in mods.ALL if m.id == "dns" or m.scan(ctx).status == "ok"]
        configured = self.verify_results(ctx, active)
        self.show_checks(configured)
        if args.iran:
            self.show_iran()
        self.send_to_checker(args, lambda lang: integration.verify_report(lang, configured))
        return 0 if all(ok for _, ok, _, _ in configured) else 1

    def show_iran(self):
        self.ui.heading(self.tr("iran_title"))
        ip = iran.public_ip()
        outcome = iran.reach(ip) if ip else None
        if outcome is None:
            self.ui.warn(self.tr("iran_unavailable"))
        else:
            ok, total = outcome
            (self.ui.ok if total and ok == total else self.ui.bad)(self.tr("iran_result", ok=ok, total=total))

    def dns_test(self):
        self.ui.heading(self.tr("dns_test_title"))
        rows = (self.dns_benchmark or benchmark)()
        for row in rows:
            if row["median_ms"] is None:
                self.ui.bad("%-10s  no answer" % row["id"])
            else:
                line = "%-10s  %6.1f ms   %d/%d failed" % (row["id"], row["median_ms"], row["fail"], row["total"])
                (self.ui.ok if row["fail"] == 0 else self.ui.warn)(line)
        return 0

    def integrate_cmd(self, args):
        if not self.need_root():
            return 2
        if args.remove:
            ids = [i for i in self.engine.run_ids()
                   if (self.engine.load(i) or {}).get("modules") == [bridge.MODULE_ID]
                   and self.engine.load(i)["status"] == "applied"]
            if not ids:
                self.ui.warn(self.tr("integrate_none"))
                return 1
            self.engine.undo(ids[-1])
            self.ui.ok(self.tr("integrate_removed"))
            return 0
        ctx = self.context()
        plan = bridge.plan(ctx)
        self.show_plans([plan])
        if plan.empty:
            return 1 if plan.skip and plan.skip[0] == "integrate_no_checker" else 0
        self.ui.p("")
        self.ui.info(self.tr("bridge_note"))
        if not args.yes and self.input_fn(self.tr("ask_integrate")).strip().lower() not in ("y", "yes"):
            self.ui.p(self.tr("cancelled"))
            return 1
        try:
            self.engine.apply([plan])
        except ApplyError as exc:
            self.ui.bad(self.tr("apply_failed", error=exc))
            return 1
        self.ui.ok(self.tr("integrate_done"))
        return 0

    # menu -------------------------------------------------------------
    def menu(self):
        self.ui.banner(self.lang, __version__)
        entries = [("1", "menu_scan"), ("2", "menu_recommended"), ("3", "menu_vpn"),
                   ("4", "menu_dns"), ("5", "menu_undo"), ("0", "menu_exit")]
        parser = make_parser()
        while True:
            self.ui.heading(self.tr("menu_title"))
            for key, label in entries:
                self.ui.p("   %s) %s" % (key, self.tr(label)))
            choice = self.input_fn("> ").strip()
            if choice == "1":
                self.scan_cmd(parser.parse_args(["scan"]))
            elif choice == "2":
                self.apply_cmd(parser.parse_args(["apply", "--profile", "recommended"]))
            elif choice == "3":
                self.apply_cmd(parser.parse_args(["apply", "--profile", "vpn"]))
            elif choice == "4":
                self.dns_test()
            elif choice == "5":
                self.undo_cmd(parser.parse_args(["undo"]))
            elif choice in ("0", "q", ""):
                return 0
            else:
                self.ui.warn(self.tr("bad_choice"))


def main(argv=None, app=None):
    parser = make_parser()
    args = parser.parse_args(argv)
    app = app or App()
    app.lang = app.resolve_lang(args)
    command = args.command or ("menu" if sys.stdin.isatty() else "scan")
    if command == "version":
        print(__version__)
        return 0
    if command == "scan":
        return app.scan_cmd(args)
    if command == "menu":
        return app.menu()
    if command == "plan":
        return app.plan_cmd(args)
    if command == "apply":
        return app.apply_cmd(args)
    if command == "undo":
        return app.undo_cmd(args)
    if command == "confirm":
        return app.confirm_cmd()
    if command == "history":
        return app.history_cmd()
    if command == "verify":
        return app.verify_cmd(args)
    if command == "dns-test":
        return app.dns_test()
    if command == "integrate":
        return app.integrate_cmd(args)
    if command == "agent":
        from .agent import serve
        serve()
        return 0
    return 2
