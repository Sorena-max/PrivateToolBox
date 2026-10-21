import unittest

from privatetoolbox import agent
from tests.helpers import server


class FakeRunner:
    def __init__(self, code=0, output="done"):
        self.calls = []
        self.code, self.output = code, output

    def __call__(self, argv, timeout):
        self.calls.append((argv, timeout))
        return self.code, self.output


def ask(request, runner=None):
    runner = runner or FakeRunner()
    return agent.execute(request, runner=runner, system=server()), runner


class BuildArgvTests(unittest.TestCase):
    def test_read_only_commands(self):
        for cmd in ("scan", "history", "dns-test", "confirm"):
            self.assertEqual(agent.build_argv({"cmd": cmd}), ["--lang", "en", cmd])

    def test_language(self):
        self.assertEqual(agent.build_argv({"cmd": "scan", "lang": "fa"})[:2], ["--lang", "fa"])
        with self.assertRaises(agent.BadRequest):
            agent.build_argv({"cmd": "scan", "lang": "../../x"})

    def test_apply_always_holds_and_never_asks(self):
        argv = agent.build_argv({"cmd": "apply", "profile": "vpn"})
        for flag in ("--yes", "--hold", "--no-notify"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("--rollback") + 1], "180")

    def test_plan_does_not_get_apply_flags(self):
        argv = agent.build_argv({"cmd": "plan", "profile": "bot"})
        self.assertNotIn("--yes", argv)

    def test_profile_or_modules_are_required_and_checked(self):
        with self.assertRaises(agent.BadRequest):
            agent.build_argv({"cmd": "apply"})
        with self.assertRaises(agent.BadRequest):
            agent.build_argv({"cmd": "apply", "profile": "nope"})
        with self.assertRaises(agent.BadRequest):
            agent.build_argv({"cmd": "apply", "modules": ["bbr", "rm -rf /"]})
        self.assertEqual(agent.build_argv({"cmd": "plan", "modules": ["bbr", "dns"]})[-2:], ["bbr", "dns"])

    def test_options_are_validated(self):
        argv = agent.build_argv({"cmd": "plan", "profile": "vpn", "opts": {
            "dns": "google", "ssh_port": 2222, "open": ["8443", "51820/udp"], "ssh_keys_only": True}})
        self.assertIn("--dns", argv)
        self.assertIn("2222", argv)
        self.assertEqual(argv.count("--open"), 2)
        self.assertIn("--ssh-keys-only", argv)

    def test_option_injection_is_rejected(self):
        bad_requests = [
            {"cmd": "plan", "profile": "vpn", "opts": {"dns": "--help"}},
            {"cmd": "plan", "profile": "vpn", "opts": {"open": ["443; reboot"]}},
            {"cmd": "plan", "profile": "vpn", "opts": {"open": ["--yes"]}},
            {"cmd": "plan", "profile": "vpn", "opts": {"exclude": ["-x"]}},
            {"cmd": "plan", "profile": "vpn", "opts": {"ssh_port": "22"}},
            {"cmd": "plan", "profile": "vpn", "opts": {"ssh_port": 70000}},
            {"cmd": "plan", "profile": "vpn", "opts": {"ssh_port": True}},
            {"cmd": "plan", "profile": "vpn", "opts": {"swap_mb": 10 ** 9}},
            {"cmd": "plan", "profile": "vpn", "opts": {"ssh_keys_only": "yes"}},
            {"cmd": "plan", "profile": "vpn", "opts": {"unknown": 1}},
            {"cmd": "plan", "profile": "vpn", "opts": ["--yes"]},
            {"cmd": "undo", "run": "last; id"},
            {"cmd": "undo", "run": "--all"},
            {"cmd": "apply", "profile": "vpn", "rollback": 5},
            {"cmd": "rm"},
            {"cmd": None},
        ]
        for request in bad_requests:
            with self.assertRaises(agent.BadRequest, msg=request):
                agent.build_argv(request)

    def test_undo(self):
        self.assertEqual(agent.build_argv({"cmd": "undo"})[-2:], ["undo", "last"])
        self.assertEqual(agent.build_argv({"cmd": "undo", "run": "20260101-120000"})[-1], "20260101-120000")

    def test_no_argument_ever_starts_like_an_unvetted_flag(self):
        argv = agent.build_argv({"cmd": "apply", "modules": ["firewall"],
                                 "opts": {"open": ["8443"], "dns": "keep"}})
        allowed = {"--lang", "--yes", "--hold", "--no-notify", "--rollback", "--open", "--dns"}
        self.assertTrue(all(a in allowed for a in argv if a.startswith("-")))


class ExecuteTests(unittest.TestCase):
    def test_ping_and_status(self):
        self.assertTrue(ask({"cmd": "ping"})[0]["ok"])
        reply, _ = ask({"cmd": "status"})
        self.assertIsNone(reply["pending"])

    def test_runs_the_installed_command_without_a_shell(self):
        reply, runner = ask({"cmd": "scan"})
        argv, timeout = runner.calls[0]
        self.assertEqual(argv[0], "/usr/local/bin/privatetoolbox")
        self.assertIsInstance(argv, list)
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["output"], "done")
        self.assertGreater(timeout, 0)

    def test_failure_is_reported(self):
        reply, _ = ask({"cmd": "scan"}, FakeRunner(code=2, output="boom"))
        self.assertEqual((reply["ok"], reply["code"]), (False, 2))

    def test_bad_requests_never_reach_the_runner(self):
        reply, runner = ask({"cmd": "apply", "profile": "vpn", "opts": {"dns": "--help"}})
        self.assertFalse(reply["ok"])
        self.assertEqual(runner.calls, [])
        self.assertFalse(agent.execute("not a dict", runner=runner, system=server())["ok"])

    def test_output_is_cleaned_and_capped(self):
        reply, _ = ask({"cmd": "scan"}, FakeRunner(output="\x1b[32mok\x1b[0m\r\n" + "x" * 50000))
        self.assertNotIn("\x1b", reply["output"])
        self.assertLessEqual(len(reply["output"]), agent.MAX_OUTPUT)

    def test_only_one_job_at_a_time(self):
        agent.LOCK.acquire()
        try:
            reply, runner = ask({"cmd": "scan"})
        finally:
            agent.LOCK.release()
        self.assertEqual(reply["error"], "busy")
        self.assertEqual(runner.calls, [])

    def test_apply_reports_a_pending_confirmation(self):
        system = server()
        run_id = "20260101-120000"
        system.write("/var/lib/privatetoolbox/runs/%s.json" % run_id, "{}")
        system.responses.insert(0, (("systemctl", "is-active", "privatetoolbox-rollback-%s.timer" % run_id),
                                    (0, "active\n")))
        reply = agent.execute({"cmd": "apply", "profile": "bot"}, runner=FakeRunner(), system=system)
        self.assertEqual(reply["pending"], run_id)


if __name__ == "__main__":
    unittest.main()
