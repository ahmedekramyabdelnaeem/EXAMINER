import unittest

from core.banner import BANNER_LINES, banner_width
from core.menu import Menu, MenuItem
from utils.output import UserCancelled


class FakeUI:
    def __init__(self, inputs):
        self.inputs = list(inputs)
        self.log = []

    def clear(self): pass
    def print(self, message="", style=""): self.log.append(str(message))
    def rule(self, title=""): self.log.append(title)
    def menu_item(self, key, label): self.log.append(f"[{key}] {label}")
    def error(self, m): self.log.append("ERR " + m)
    def warning(self, m): self.log.append("WARN " + m)
    def info(self, m): self.log.append("INFO " + m)
    def pause(self, message=""): pass

    def ask(self, prompt, default=None):
        if not self.inputs:
            raise UserCancelled()
        return self.inputs.pop(0)


class TestMenu(unittest.TestCase):
    def test_dispatch_and_exit(self):
        calls = []
        ui = FakeUI(["1", "0"])
        Menu(ui, "T", [MenuItem("1", "One", lambda: calls.append(1))]).run()
        self.assertEqual(calls, [1])

    def test_invalid_input_does_not_crash(self):
        ui = FakeUI(["x", "", "99", "0"])
        Menu(ui, "T", [MenuItem("1", "One", lambda: None)]).run()
        self.assertEqual(sum(1 for l in ui.log if l.startswith("ERR")), 2)
        self.assertEqual(sum(1 for l in ui.log if l.startswith("WARN")), 1)

    def test_handler_exception_is_contained(self):
        def boom():
            raise RuntimeError("kaboom")
        ui = FakeUI(["1", "0"])
        Menu(ui, "T", [MenuItem("1", "Boom", boom)]).run()
        self.assertTrue(any("kaboom" in l for l in ui.log))

    def test_keyboard_interrupt_in_handler(self):
        def interrupt():
            raise KeyboardInterrupt
        ui = FakeUI(["1", "0"])
        Menu(ui, "T", [MenuItem("1", "I", interrupt)]).run()
        self.assertTrue(any("cancelled" in l for l in ui.log))

    def test_eof_exits(self):
        Menu(FakeUI([]), "T", [MenuItem("1", "One", lambda: None)]).run()

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            Menu(FakeUI([]), "T", [MenuItem("1", "a"), MenuItem("1", "b")])
        with self.assertRaises(ValueError):
            Menu(FakeUI([]), "T", [MenuItem("0", "a")])

    def test_case_and_whitespace_insensitive(self):
        calls = []
        ui = FakeUI(["  A ", "0"])
        Menu(ui, "T", [MenuItem("a", "A", lambda: calls.append(1))]).run()
        self.assertEqual(calls, [1])


class TestBanner(unittest.TestCase):
    def test_banner_is_ascii_and_fits(self):
        for line in BANNER_LINES:
            self.assertTrue(line.isascii())
        self.assertLessEqual(banner_width(), 78)


if __name__ == "__main__":
    unittest.main()
