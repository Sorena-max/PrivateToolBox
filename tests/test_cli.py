import json
import unittest
from unittest import mock

from privatetoolbox import cli, notify
from privatetoolbox.actions import Finding
from tests.helpers import quiet_ui, server

UFW_ACTIVE = (("ufw", "status"), (0, "Status: active\n22/tcp ALLOW Anywhere\n443/tcp ALLOW Anywhere\n"))
FIREWALLD_OFF = (("systemctl", "is-active", "firewalld"), (3, "inactive\n"))
F2B_ON = (("systemctl", "is-active", "fail2ban"), (0, "active\n"))
CHECKER_ON = (("systemctl", "is-active", "privatechecker"), (0, "active\n"))
CHECKER_CONFIG = json.dumps({"token": "TOKEN", "owner_id": 42, "language": "fa"})


def checker_system(**kw):
    """A server that also runs a configured PrivateChecker bot."""
    responses = [CHECKER_ON] + list(kw.pop("responses", []))
    return server(files={"/var/lib/privatechecker/config.json": CHECKER_CONFIG},
                  responses=responses, **kw)


def make_app(system=None, answers=None, keep="", benchmark=None, **kw):
    system = system or server()
    ui, stream = quiet_ui()
    queue = list(answers or [])
    asked = []

    def answer(prompt):
        asked.append(prompt)
        return queue.pop(0) if queue else ""
    app = cli.App(system=system, ui=ui, input_fn=answer, ask_keep=lambda seconds: keep,
                  dns_benchmark=benchmark)
    app.interactive = False
    app.asked = asked
    app.stream = stream
    return app


def run(app, *argv):
    return cli.main(list(argv), app=app)


def output(app):
    return app.stream.getvalue()


class ScoreTests(unittest.TestCase):
    def test_score(self):
        f = lambda status, weight: Finding("m", status, "k", {}, weight)
        self.assertEqual(cli.score([f("ok", 10), f("ok", 10)]), 100)
        self.assertEqual(cli.score([f("todo", 10)]), 0)
        self.assertEqual(cli.score([f("ok", 10), f("todo", 30)]), 25)
        self.assertEqual(cli.score([f("na", 0), f("info", 0)]), 100)


class ReadOnlyCommandTests(unittest.TestCase):
    def test_scan_changes_nothing(self):
        system = server()
        files = dict(system.files)
        app = make_app(system)
        self.assertEqual(run(app, "scan"), 0)
        self.assertEqual(system.files, files)
        text = output(app)
        self.assertIn("Firewall", text)
        self.assertIn("Score", text)

    def test_plan_changes_nothing_and_lists_actions(self):
        system = server()
        files = dict(system.files)
        app = make_app(system)
        self.assertEqual(run(app, "plan", "--profile", "recommended"), 0)
        self.assertEqual(system.files, files)
        self.assertIn("- sysctl net.ipv4.tcp_syncookies=1", output(app))
        self.assertFalse(system.ran("ufw", "--force", "enable"))

    def test_persian_output(self):
        app = make_app()
        run(app, "--lang", "fa", "scan")
        self.assertIn("فایروال", output(app))
        self.assertIn("امتیاز", output(app))

    def test_terminal_output_is_english_by_default(self):
        app = make_app()
        run(app, "scan")
        self.assertIn("Firewall", output(app))
        self.assertNotRegex(output(app), "[\u0600-\u06ff]")

    def test_unknown_module(self):
        app = make_app()
        self.assertEqual(run(app, "plan", "nonsense"), 2)

    def test_dns_test_prints_a_ranking(self):
        rows = [{"id": "cloudflare", "ips": [], "median_ms": 9.0, "fail": 0, "total": 10},
                {"id": "quad9", "ips": [], "median_ms": None, "fail": 10, "total": 10}]
        app = make_app(benchmark=lambda: rows)
        run(app, "dns-test")
        self.assertIn("cloudflare", output(app))
        self.assertIn("no answer", output(app))

    def test_menu_runs_a_scan_and_exits(self):
        app = make_app(answers=["1", "0"])
        self.assertEqual(run(app, "menu"), 0)
        self.assertIn("Score", output(app))


class ApplyTests(unittest.TestCase):
    def test_apply_without_root_is_refused(self):
        app = make_app(server(root=False))
        self.assertEqual(run(app, "apply", "--yes", "bbr"), 2)

    def test_harmless_modules_do_not_arm_a_timer(self):
        system = server()
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "bbr", "sysctl"), 0)
        self.assertFalse(system.ran("systemd-run"))
        self.assertEqual(system.sysctl_get("net.ipv4.tcp_congestion_control"), "bbr")
        self.assertIn("Score after", output(app))

    def test_asks_before_applying(self):
        system = server()
        app = make_app(system, answers=["n"])
        self.assertEqual(run(app, "apply", "bbr"), 1)
        self.assertEqual(system.sysctl_get("net.ipv4.tcp_congestion_control"), "cubic")

    def test_access_modules_arm_the_rollback_timer_first(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "firewall"), 0)
        armed = next(i for i, c in enumerate(system.commands) if c[0] == "systemd-run")
        first_change = next(i for i, c in enumerate(system.commands) if c[:3] == ["ufw", "default", "deny"])
        self.assertLess(armed, first_change)
        timer = [c for c in system.commands if c[0] == "systemd-run"][0]
        self.assertIn("--on-active=120", timer)
        self.assertIn("undo", timer)

    def test_headless_apply_confirms_when_every_check_passes(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system)
        run(app, "apply", "--yes", "firewall")
        self.assertTrue(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                            for c in system.commands))

    def test_failed_check_leaves_the_timer_to_roll_back(self):
        system = server(responses=[FIREWALLD_OFF])       # ufw stays "inactive" after enabling
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "firewall"), 3)
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                             for c in system.commands))

    def test_no_timer_means_no_safety_net_and_must_be_explicit(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system)
        run(app, "apply", "--yes", "--no-rollback", "firewall")
        self.assertFalse(system.ran("systemd-run"))

    def test_refuses_when_the_timer_cannot_be_armed(self):
        system = server(responses=[(("systemd-run",), (1, "no systemd"))])
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "firewall"), 2)
        self.assertFalse(system.ran("ufw", "--force", "enable"))

    def test_a_failing_step_is_rolled_back_and_the_timer_cancelled(self):
        system = server(responses=[FIREWALLD_OFF])
        system.fail_on = ["ufw", "--force", "enable"]
        before = system.read("/etc/ufw/user.rules")
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "firewall"), 1)
        self.assertEqual(system.read("/etc/ufw/user.rules"), before)
        self.assertTrue(system.ran("ufw", "--force", "disable"))
        self.assertTrue(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                            for c in system.commands))

    def test_interactive_keep_cancels_the_rollback(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system, answers=["y"], keep="yes")
        self.assertEqual(run(app, "apply", "firewall"), 0)
        self.assertTrue(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                            for c in system.commands))

    def test_interactive_silence_lets_the_rollback_fire(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system, answers=["y"], keep="")
        self.assertEqual(run(app, "apply", "firewall"), 3)
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                             for c in system.commands))

    def test_already_configured_does_nothing(self):
        system = server()
        system.set_sysctl("net.ipv4.tcp_congestion_control", "bbr")
        system.set_sysctl("net.core.default_qdisc", "fq")
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "bbr"), 0)
        self.assertIn("Nothing to do", output(app))

    def test_notify_sends_a_summary(self):
        app = make_app(checker_system())
        with mock.patch.object(notify, "send") as send:
            run(app, "apply", "--yes", "--notify", "bbr")
        self.assertIn(" -> ", send.call_args[0][1])
        self.assertNotIn("TOKEN", send.call_args[0][1])


class UndoAndHistoryTests(unittest.TestCase):
    def test_undo_last_restores_everything(self):
        system = server()
        app = make_app(system)
        run(app, "apply", "--yes", "sysctl", "bbr")
        self.assertEqual(system.sysctl_get("net.ipv4.tcp_syncookies"), "1")
        self.assertEqual(run(app, "undo"), 0)
        self.assertEqual(system.sysctl_get("net.ipv4.tcp_syncookies"), "0")
        self.assertIsNone(system.read("/etc/sysctl.d/91-privatetoolbox-net.conf"))

    def test_undo_with_nothing_to_undo(self):
        self.assertEqual(run(make_app(), "undo"), 1)

    def test_history_lists_runs(self):
        app = make_app()
        run(app, "apply", "--yes", "bbr")
        run(app, "history")
        self.assertIn("applied", output(app))

    def test_confirm_without_a_pending_rollback(self):
        self.assertEqual(run(make_app(), "confirm"), 1)

    def test_confirm_cancels_the_pending_rollback(self):
        system = server(responses=[FIREWALLD_OFF])
        app = make_app(system)
        run(app, "apply", "--yes", "firewall")          # ends with a pending timer (checks failed)
        run_id = app.engine.run_ids()[-1]
        system.responses.insert(0, ((("systemctl", "is-active", "privatetoolbox-rollback-%s.timer" % run_id)),
                                    (0, "active\n")))
        system.commands.clear()
        self.assertEqual(run(app, "confirm"), 0)
        self.assertTrue(system.ran("systemctl", "stop", "privatetoolbox-rollback-%s.timer" % run_id))


class VerifyTests(unittest.TestCase):
    def test_verify_reports_configured_parts(self):
        system = server(responses=[F2B_ON])
        app = make_app(system)
        run(app, "apply", "--yes", "bbr")
        self.assertEqual(run(app, "verify"), 0)
        self.assertIn("congestion control is bbr", output(app))

    def test_verify_notify(self):
        app = make_app(checker_system())
        with mock.patch.object(notify, "send") as send:
            run(app, "verify", "--notify")
        self.assertIn("PrivateToolBox", send.call_args[0][1])

class PrivateCheckerReportTests(unittest.TestCase):
    def ask(self, system, argv, answers, interactive=True):
        app = make_app(system, answers=answers)
        app.interactive = interactive
        with mock.patch.object(notify, "send", return_value=True) as send:
            code = run(app, *argv)
        return app, send, code

    def test_a_person_is_asked_when_privatechecker_is_running(self):
        app, send, _ = self.ask(checker_system(), ["apply", "bbr"], ["y", "y"])
        self.assertIn("Send this report to your Telegram bot", output(app) + "".join(app.asked))
        self.assertTrue(send.called)

    def test_saying_no_sends_nothing(self):
        _, send, _ = self.ask(checker_system(), ["apply", "bbr"], ["y", "n"])
        self.assertFalse(send.called)

    def test_scripts_are_never_asked(self):
        _, send, _ = self.ask(checker_system(), ["apply", "--yes", "bbr"], [])
        self.assertFalse(send.called)

    def test_no_notify_skips_the_question(self):
        _, send, _ = self.ask(checker_system(), ["apply", "--no-notify", "bbr"], ["y"])
        self.assertFalse(send.called)

    def test_no_question_when_privatechecker_is_not_running(self):
        _, send, _ = self.ask(server(), ["apply", "bbr"], ["y", "y"])
        self.assertFalse(send.called)

    def test_notify_without_privatechecker_warns(self):
        app, send, _ = self.ask(server(), ["apply", "--yes", "--notify", "bbr"], [], interactive=False)
        self.assertFalse(send.called)
        self.assertIn("not set up", output(app))

    def test_the_report_uses_the_bot_language(self):
        _, send, _ = self.ask(checker_system(), ["apply", "--yes", "--notify", "bbr"], [], interactive=False)
        text = send.call_args[0][1]
        self.assertIn("امتیاز", text)                      # PrivateChecker is set to Persian
        self.assertIn("BBR", text)

    def test_the_report_holds_no_secrets(self):
        _, send, _ = self.ask(checker_system(), ["apply", "--yes", "--notify", "bbr"], [], interactive=False)
        self.assertNotIn("TOKEN", send.call_args[0][1])

    def test_terminal_stays_english_when_the_bot_speaks_persian(self):
        app, _, _ = self.ask(checker_system(), ["apply", "--yes", "--notify", "bbr"], [], interactive=False)
        self.assertNotRegex(output(app), "[\u0600-\u06ff]")


class HoldTests(unittest.TestCase):
    def test_hold_applies_but_waits_for_confirmation(self):
        system = server(responses=[UFW_ACTIVE, FIREWALLD_OFF])
        app = make_app(system)
        self.assertEqual(run(app, "apply", "--yes", "--hold", "firewall"), 0)
        self.assertTrue(system.ran("ufw", "--force", "enable"))
        self.assertFalse(any(c[:2] == ["systemctl", "stop"] and c[2].endswith(".timer")
                             for c in system.commands))
        self.assertIn("not kept yet", output(app))


class IntegrateTests(unittest.TestCase):
    CHECKER_USER = (("id", "-u", "privatechecker"), (0, "999\n"))

    def test_needs_privatechecker(self):
        system = server(responses=[(("id", "-u", "privatechecker"), (1, ""))])
        self.assertEqual(run(make_app(system), "integrate", "--yes"), 1)
        self.assertFalse(system.ran("groupadd"))

    def test_sets_up_the_group_service_and_restarts_the_bot(self):
        system = server(responses=[self.CHECKER_USER])
        app = make_app(system)
        self.assertEqual(run(app, "integrate", "--yes"), 0)
        self.assertTrue(system.ran("groupadd", "-f", "privatetoolbox"))
        self.assertTrue(system.ran("usermod", "-aG", "privatetoolbox", "privatechecker"))
        self.assertIn("ExecStart=/usr/local/bin/privatetoolbox agent",
                      system.read("/etc/systemd/system/privatetoolbox-agent.service"))
        self.assertTrue(system.ran("systemctl", "restart", "privatetoolbox-agent"))
        self.assertTrue(system.ran("systemctl", "restart", "privatechecker"))

    def test_asks_first(self):
        system = server(responses=[self.CHECKER_USER])
        self.assertEqual(run(make_app(system, answers=["n"]), "integrate"), 1)
        self.assertFalse(system.ran("groupadd"))

    def test_remove_takes_everything_back(self):
        system = server(responses=[self.CHECKER_USER])
        app = make_app(system)
        run(app, "integrate", "--yes")
        self.assertEqual(run(app, "integrate", "--remove"), 0)
        self.assertIsNone(system.read("/etc/systemd/system/privatetoolbox-agent.service"))
        self.assertTrue(system.ran("gpasswd", "-d", "privatechecker", "privatetoolbox"))

    def test_remove_when_not_enabled(self):
        self.assertEqual(run(make_app(), "integrate", "--remove"), 1)

    def test_already_enabled(self):
        system = server(files={"/etc/systemd/system/privatetoolbox-agent.service": ""},
                        responses=[self.CHECKER_USER])
        app = make_app(system)
        run(app, "integrate", "--yes")
        self.assertIn("already enabled", output(app))
        self.assertFalse(system.ran("groupadd"))


if __name__ == "__main__":
    unittest.main()
