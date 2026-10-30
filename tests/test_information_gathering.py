import unittest
from types import SimpleNamespace

from modules.information_gathering.module import InformationGatheringModule


class FakeUI:
    def __init__(self):
        self.items = []

    def print(self, *args, **kwargs):
        pass

    def rule(self, *args, **kwargs):
        pass

    def menu_item(self, key, label):
        self.items.append((key, label))

    def clear(self):
        pass

    def ask(self, *args, **kwargs):
        return "0"

    def panel(self, *args, **kwargs):
        pass

    def table(self, *args, **kwargs):
        pass

    def warning(self, *args, **kwargs):
        pass

    def error(self, *args, **kwargs):
        pass


class TestInformationGathering(unittest.TestCase):
    def test_menu_is_safe_and_has_expected_actions(self):
        ui = FakeUI()
        engine = SimpleNamespace(
            ui=ui,
            config=SimpleNamespace(get=lambda key: 3.0),
            logger=SimpleNamespace(debug=lambda *a, **k: None),
            confirm_scope=lambda *a, **k: True,
        )
        module = InformationGatheringModule(engine)
        module.menu()
        labels = [label for _, label in ui.items]
        self.assertIn("DNS Records", labels)
        self.assertIn("HTTP Response Headers", labels)
        self.assertIn("TLS Certificate Summary", labels)
        self.assertIn("Subdomain Enumeration (not enabled)", labels)


if __name__ == "__main__":
    unittest.main()
