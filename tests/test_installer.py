import os
import re
import shutil
import subprocess
import unittest

from privatetoolbox import __version__

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALLER = os.path.join(ROOT, "install.sh")


def installer_text():
    with open(INSTALLER, encoding="utf-8") as fh:
        return fh.read()


class InstallerTests(unittest.TestCase):
    def test_version_matches_the_package(self):
        found = re.search(r'^PT_VERSION="([^"]+)"', installer_text(), re.M)
        self.assertIsNotNone(found)
        self.assertEqual(found.group(1), __version__)

    def test_uses_lf_line_endings(self):
        with open(INSTALLER, "rb") as fh:
            self.assertNotIn(b"\r", fh.read())

    def test_credits_the_project_and_states_it_is_free(self):
        text = installer_text()
        self.assertIn("GitHub:", text)
        self.assertIn("Sorena-max", text)
        self.assertIn("completely free", text)
        self.assertIn("PrivateToolBox (Private Tool)", text)

    def test_terminal_text_has_no_persian(self):
        self.assertIsNone(re.search("[؀-ۿ]", installer_text()))

    def test_animation_is_off_for_automation(self):
        text = installer_text()
        self.assertIn("--fast", text)
        self.assertIn('if [ "$FAST" -eq 0 ] && [ "$NON_INTERACTIVE" -eq 0 ]; then SLOW=1; fi', text)

    def test_installer_does_not_touch_server_settings(self):
        text = installer_text()
        for forbidden in ("ufw ", "sysctl -w", "systemctl enable", "sshd_config"):
            self.assertNotIn(forbidden, text, forbidden)

    def test_script_is_parsed_in_full_before_it_runs(self):
        self.assertEqual(installer_text().rstrip().splitlines()[-1], 'main "$@"')

    @unittest.skipUnless(shutil.which("bash"), "bash not available")
    def test_syntax_is_valid(self):
        result = subprocess.run(["bash", "-n", INSTALLER], stderr=subprocess.PIPE,
                                universal_newlines=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash not available")
    def test_help_works_without_root(self):
        result = subprocess.run(["bash", INSTALLER, "--help"], stdout=subprocess.PIPE,
                                universal_newlines=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--non-interactive", result.stdout)


if __name__ == "__main__":
    unittest.main()
