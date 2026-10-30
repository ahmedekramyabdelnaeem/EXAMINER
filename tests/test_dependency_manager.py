import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core.config import ConfigManager
from core.dependency_manager import DependencyManager, detect_system


def make_manager(nmap_path=""):
    tmp = tempfile.TemporaryDirectory()
    import atexit
    atexit.register(tmp.cleanup)
    cfg = ConfigManager(Path(tmp.name) / "s.json", Path(tmp.name))
    cfg.load()
    cfg.set("nmap_path", nmap_path)
    manager = DependencyManager(cfg)
    manager._tmp = tmp  # keep alive
    manager._finalizer = tmp.cleanup
    return manager


class TestDependencies(unittest.TestCase):
    def tearDown(self):
        pass
    def test_system_info(self):
        info = detect_system()
        self.assertTrue(info.os_name)
        self.assertTrue(info.python_version)

    def test_nmap_missing(self):
        manager = make_manager()
        with mock.patch("shutil.which", return_value=None), \
                mock.patch.object(DependencyManager, "_locate_nmap", return_value=(None, "")):
            status = manager.check_nmap()
        self.assertFalse(status.available)
        self.assertTrue(status.install_hint)

    def test_nmap_found(self):
        manager = make_manager()
        completed = subprocess.CompletedProcess([], 0, stdout="Nmap version 7.94 ( https://nmap.org )\n")
        with mock.patch("shutil.which", return_value="/usr/bin/nmap"), \
                mock.patch("subprocess.run", return_value=completed):
            status = manager.check_nmap()
        self.assertTrue(status.available)
        self.assertEqual(status.version, "7.94")

    def test_nmap_found_but_broken(self):
        manager = make_manager()
        with mock.patch("shutil.which", return_value="/usr/bin/nmap"), \
                mock.patch("subprocess.run", side_effect=OSError("boom")):
            status = manager.check_nmap()
        self.assertFalse(status.available)

    def test_invalid_configured_path_reported(self):
        manager = make_manager("/definitely/not/here/nmap")
        with mock.patch("shutil.which", return_value=None):
            status = manager.check_nmap()
        self.assertFalse(status.available)
        self.assertIn("Configured Nmap path", status.detail)

    def test_python_packages(self):
        statuses = manager_statuses = make_manager().check_python_packages()
        self.assertEqual({s.name for s in manager_statuses},
                         {"rich", "requests", "dnspython", "python-whois"})
        for status in statuses:
            if not status.available:
                self.assertTrue(status.install_hint)


if __name__ == "__main__":
    unittest.main()
