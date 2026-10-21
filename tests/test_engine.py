import unittest

from privatetoolbox import actions as act
from privatetoolbox.engine import ApplyError, Engine
from tests.helpers import FakeSystem, server


def plan(*actions, module="demo"):
    return act.Plan(module, list(actions))


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.sys = server()
        self.engine = Engine(self.sys, home="/state")

    def test_new_file_is_removed_by_undo(self):
        run_id = self.engine.apply([plan(act.WriteFile("/etc/new.conf", "x\n"))])
        self.assertEqual(self.sys.read("/etc/new.conf"), "x\n")
        self.engine.undo(run_id)
        self.assertIsNone(self.sys.read("/etc/new.conf"))

    def test_existing_file_is_restored_with_its_mode(self):
        self.sys.write("/etc/a.conf", "old\n", mode=0o640)
        run_id = self.engine.apply([plan(act.WriteFile("/etc/a.conf", "new\n", mode=0o644))])
        self.assertEqual(self.sys.read("/etc/a.conf"), "new\n")
        self.engine.undo(run_id)
        self.assertEqual(self.sys.read("/etc/a.conf"), "old\n")
        self.assertEqual(self.sys.modes["/etc/a.conf"], 0o640)

    def test_two_writes_to_one_file_undo_to_the_original(self):
        self.sys.write("/etc/a.conf", "v1\n")
        run_id = self.engine.apply([plan(act.WriteFile("/etc/a.conf", "v2\n"),
                                         act.WriteFile("/etc/a.conf", "v3\n"))])
        self.engine.undo(run_id)
        self.assertEqual(self.sys.read("/etc/a.conf"), "v1\n")

    def test_sysctl_value_comes_back(self):
        run_id = self.engine.apply([plan(act.Sysctl("net.core.somaxconn", "4096"))])
        self.assertTrue(self.sys.ran("sysctl", "-w", "net.core.somaxconn=4096"))
        self.engine.undo(run_id)
        self.assertTrue(self.sys.ran("sysctl", "-w", "net.core.somaxconn=128"))

    def test_run_undo_command_is_executed(self):
        run_id = self.engine.apply([plan(act.Run(["touch", "/x"], undo=["rm", "-f", "/x"]))])
        self.engine.undo(run_id)
        self.assertTrue(self.sys.ran("rm", "-f", "/x"))

    def test_snapshot_restores_files_changed_by_commands(self):
        self.sys.write("/etc/ufw/user.rules", "old rules\n")
        run_id = self.engine.apply([plan(act.Snapshot(["/etc/ufw/user.rules"],
                                                      undo_after=["ufw", "reload"]),
                                         act.WriteFile("/etc/ufw/user.rules", "changed\n"))])
        self.engine.undo(run_id)
        self.assertEqual(self.sys.read("/etc/ufw/user.rules"), "old rules\n")
        self.assertTrue(self.sys.ran("ufw", "reload"))

    def test_service_is_returned_to_its_old_state(self):
        run_id = self.engine.apply([plan(act.Service("fail2ban", enable=True, state="restarted"))])
        self.assertTrue(self.sys.ran("systemctl", "restart", "fail2ban"))
        self.engine.undo(run_id)
        self.assertTrue(self.sys.ran("systemctl", "disable", "fail2ban"))
        self.assertTrue(self.sys.ran("systemctl", "stop", "fail2ban"))

    def test_failure_rolls_back_everything_done_so_far(self):
        self.sys.write("/etc/a.conf", "old\n")
        self.sys.fail_on = ["boom"]
        with self.assertRaises(ApplyError):
            self.engine.apply([plan(act.WriteFile("/etc/a.conf", "new\n"),
                                    act.Run(["boom"]))])
        self.assertEqual(self.sys.read("/etc/a.conf"), "old\n")
        self.assertEqual(self.engine.load("last")["status"], "failed")

    def test_validate_failure_restores_the_old_file(self):
        self.sys.write("/etc/ssh/x.conf", "good\n")
        self.sys.fail_on = ["sshd", "-t"]
        with self.assertRaises(ApplyError):
            self.engine.apply([plan(act.WriteFile("/etc/ssh/x.conf", "bad\n", validate=["sshd", "-t"],
                                                  after=["systemctl", "reload", "ssh"]))])
        self.assertEqual(self.sys.read("/etc/ssh/x.conf"), "good\n")
        self.assertFalse(self.sys.ran("systemctl", "reload", "ssh"))

    def test_ignore_fail_does_not_abort(self):
        self.sys.fail_on = ["modprobe"]
        self.engine.apply([plan(act.Run(["modprobe", "x"], ignore_fail=True),
                                act.WriteFile("/etc/ok", "1\n"))])
        self.assertEqual(self.sys.read("/etc/ok"), "1\n")

    def test_undo_twice_is_refused(self):
        run_id = self.engine.apply([plan(act.WriteFile("/etc/n", "1\n"))])
        self.engine.undo(run_id)
        with self.assertRaises(ApplyError):
            self.engine.undo(run_id)

    def test_last_and_history(self):
        first = self.engine.apply([plan(act.WriteFile("/etc/n1", "1\n"))])
        second = self.engine.apply([plan(act.WriteFile("/etc/n2", "2\n"))])
        self.assertNotEqual(first, second)
        self.assertEqual(self.engine.load("last")["id"], second)
        self.assertEqual(self.engine.run_ids(), sorted([first, second]))

    def test_install_uses_the_package_manager(self):
        self.engine.apply([plan(act.Install(["ufw"]))])
        self.assertTrue(self.sys.ran("apt-get", "install", "-y", "-qq", "ufw"))

    def test_install_without_a_package_manager_fails_cleanly(self):
        sysm = FakeSystem()
        with self.assertRaises(ApplyError):
            Engine(sysm, home="/s").apply([plan(act.Install(["ufw"]))])

    def test_journal_is_private(self):
        run_id = self.engine.apply([plan(act.WriteFile("/etc/n", "1\n"))])
        self.assertEqual(self.sys.modes["/state/runs/%s.json" % run_id], 0o600)


if __name__ == "__main__":
    unittest.main()
