import json
import os
import re
import unittest

from privatetoolbox import __version__, iran, notify
from privatetoolbox.i18n import T, t
from privatetoolbox.modules import ALL
from privatetoolbox.ui import UI
from tests.helpers import FakeSystem

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORBIDDEN = {chr(code): label for code, label in (
    (0x2014, "em dash"), (0x2013, "en dash"), (0x2026, "ellipsis character"),
    (0x200C, "zero width non-joiner"), (0x00A0, "no-break space"),
    (0x202F, "narrow no-break space"), (0x2009, "thin space"), (0x200B, "zero width space"),
    (0x2018, "curly quote"), (0x2019, "curly quote"), (0x201C, "curly quote"),
    (0x201D, "curly quote"), (0x2265, "greater-or-equal sign"), (0x00D7, "multiplication sign"),
    (0x00B7, "middle dot"), (0x2192, "arrow"), (0x066A, "arabic percent sign"),
)}


def placeholders(text):
    return set(re.findall(r"\{(\w+)\}", text))


class I18nTests(unittest.TestCase):
    def test_same_keys_in_both_languages(self):
        self.assertEqual(set(T["en"]), set(T["fa"]))

    def test_same_placeholders(self):
        for key in T["en"]:
            self.assertEqual(placeholders(T["en"][key]), placeholders(T["fa"][key]), key)

    def test_every_module_has_a_title(self):
        for module in ALL:
            self.assertIn("mod_" + module.id, T["en"])

    def test_missing_key_falls_back_to_the_key(self):
        self.assertEqual(t("fa", "no_such_key"), "no_such_key")


class StyleTests(unittest.TestCase):
    def test_no_typographic_tells_in_the_project(self):
        problems = []
        for base, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__")]
            for name in files:
                if not name.endswith((".py", ".md", ".sh", ".yml")):
                    continue
                path = os.path.join(base, name)
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                for char, label in FORBIDDEN.items():
                    if char in text:
                        problems.append("%s: %s" % (os.path.relpath(path, ROOT), label))
        self.assertEqual(problems, [])


class NotifyTests(unittest.TestCase):
    def config(self):
        return FakeSystem(files={"/var/lib/privatechecker/config.json": json.dumps(
            {"token": "123:abc", "owner_id": 42, "api_base": "https://api.telegram.org"})})

    def test_sends_to_the_checker_owner(self):
        sent = {}

        def post(url, body):
            sent["url"], sent["body"] = url, json.loads(body)
            return True
        self.assertTrue(notify.send(self.config(), "hello", post=post))
        self.assertTrue(sent["url"].endswith("/bot123:abc/sendMessage"))
        self.assertEqual(sent["body"]["chat_id"], 42)

    def test_silent_when_checker_is_not_installed(self):
        self.assertFalse(notify.send(FakeSystem(), "hello", post=lambda u, b: True))

    def test_network_errors_are_swallowed(self):
        def post(url, body):
            raise OSError("down")
        self.assertFalse(notify.send(self.config(), "hello", post=post))


class IranTests(unittest.TestCase):
    NODES = {"nodes": {"de1.node.check-host.net": {"location": ["de", "Germany", "Nuremberg"]},
                       "ir1.node.check-host.net": {"location": ["ir", "Iran", "Tehran"]},
                       "ir2.node.check-host.net": {"location": ["ir", "Iran", "Isfahan"]}}}

    def test_count_ok(self):
        ok = [[["OK", 0.05, "x"], ["OK", 0.05], ["TIMEOUT", 3.0], ["OK", 0.04]]]
        self.assertEqual(iran.count_ok(ok), 3)
        self.assertEqual(iran.count_ok([[["TIMEOUT", 3.0]]]), 0)
        self.assertIsNone(iran.count_ok(None))
        self.assertIsNone(iran.count_ok([None]))

    def test_reach(self):
        def get(path):
            if path.startswith("/nodes/hosts"):
                return self.NODES
            if path.startswith("/check-ping"):
                return {"request_id": "r1"}
            return {"ir1.node.check-host.net": [[["OK", 0.05]] * 4],
                    "ir2.node.check-host.net": [[["TIMEOUT", 3.0]] * 4]}
        self.assertEqual(iran.reach("203.0.113.5", get=get, sleep=lambda s: None), (1, 2))

    def test_rate_limit_is_retried_then_gives_up(self):
        calls = []

        def get(path):
            calls.append(path)
            if path.startswith("/nodes/hosts"):
                return self.NODES
            raise OSError("limit_exceeded")
        self.assertIsNone(iran.reach("203.0.113.5", get=get, sleep=lambda s: None))
        self.assertEqual(len([c for c in calls if c.startswith("/check-ping")]), 3)

    def test_api_down(self):
        def get(path):
            raise OSError("down")
        self.assertIsNone(iran.reach("203.0.113.5", get=get, sleep=lambda s: None))


class UiTests(unittest.TestCase):
    def test_plain_output_has_no_escape_codes(self):
        import io
        stream = io.StringIO()
        ui = UI(stream=stream, color=False, utf8=False)
        ui.banner("en", __version__)
        ui.ok("x")
        ui.bad("y")
        self.assertNotIn("\033", stream.getvalue())
        self.assertIn("GitHub: Sorena-max", stream.getvalue())
        self.assertIn("completely free", stream.getvalue())

    def test_bar_bounds(self):
        ui = UI(stream=__import__("io").StringIO(), color=False, utf8=False)
        self.assertIn("0/100", ui.bar(0))
        self.assertIn("100/100", ui.bar(100))


if __name__ == "__main__":
    unittest.main()
