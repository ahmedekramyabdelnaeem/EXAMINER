import json
import tempfile
import unittest
from pathlib import Path

from core.config import DEFAULTS, ConfigError, ConfigManager


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "config" / "settings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def make(self):
        return ConfigManager(self.path, self.root)

    def test_creates_defaults(self):
        cfg = self.make()
        self.assertEqual(cfg.load(), [])
        self.assertTrue(self.path.exists())
        self.assertEqual(cfg.as_dict(), DEFAULTS)

    def test_roundtrip(self):
        cfg = self.make()
        cfg.load()
        cfg.set("default_timeout", "5")
        cfg.set("default_speed", "FAST")
        cfg.set("colors_enabled", "off")
        self.assertTrue(cfg.save())
        again = self.make()
        self.assertEqual(again.load(), [])
        self.assertEqual(again.get("default_timeout"), 5.0)
        self.assertEqual(again.get("default_speed"), "fast")
        self.assertFalse(again.get("colors_enabled"))

    def test_invalid_set(self):
        cfg = self.make()
        for key, value in (("default_timeout", "abc"), ("default_timeout", True),
                           ("default_speed", "warp"), ("preferred_engine", 5),
                           ("colors_enabled", "maybe"), ("nope", 1), ("log_level", "LOUD")):
            with self.assertRaises(ConfigError, msg=f"{key}={value}"):
                cfg.set(key, value)

    def test_corrupt_file_is_backed_up(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text("{not json", encoding="utf-8")
        cfg = self.make()
        warnings = cfg.load()
        self.assertTrue(warnings)
        self.assertEqual(cfg.as_dict(), DEFAULTS)
        self.assertTrue(self.path.with_name("settings.json.bak").exists())
        json.loads(self.path.read_text(encoding="utf-8"))

    def test_bad_values_fall_back(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps({"default_timeout": -5, "mystery": 1,
                                         "default_speed": "fast"}), encoding="utf-8")
        cfg = self.make()
        warnings = cfg.load()
        self.assertEqual(len(warnings), 2)
        self.assertEqual(cfg.get("default_timeout"), DEFAULTS["default_timeout"])
        self.assertEqual(cfg.get("default_speed"), "fast")

    def test_bom_file_ok(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"default_speed": "slow"}).encode())
        cfg = self.make()
        self.assertEqual(cfg.load(), [])
        self.assertEqual(cfg.get("default_speed"), "slow")

    def test_subdir(self):
        cfg = self.make()
        cfg.load()
        cfg.set("output_dir", str(self.root / "out"))
        self.assertEqual(cfg.subdir("reports"), self.root / "out" / "reports")
        self.assertTrue((self.root / "out" / "reports").is_dir())


if __name__ == "__main__":
    unittest.main()
