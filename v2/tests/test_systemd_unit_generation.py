import unittest
from unittest.mock import patch, mock_open
from pathlib import Path
import os
from sys import path as path

# Add src directory to path
path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.dar_backup_systemd import (
    generate_service,
    generate_timer,
    generate_cleanup_service,
    build_exec_command,
    FLAGS,
    TIMINGS
)

class TestDarBackupUnitGenerator(unittest.TestCase):

    def setUp(self):
        self.venv = "/fake/venv"
        self.dar_path = "/opt/dar"

    def test_build_exec_command_with_dar(self):
        cmd = build_exec_command(self.venv, "-F", self.dar_path)
        self.assertIn("PATH=/opt/dar:$PATH", cmd)
        self.assertIn("dar-backup -F", cmd)

    def test_build_exec_command_without_dar(self):
        cmd = build_exec_command(self.venv, "-F")
        self.assertNotIn("PATH=", cmd)
        self.assertIn("dar-backup -F", cmd)

    def test_generate_service(self):
        content = generate_service("FULL", self.venv, self.dar_path)
        self.assertIn("Description=dar-backup FULL", content)
        self.assertIn("ExecStart=/bin/bash -c", content)

    def test_generate_timer(self):
        content = generate_timer("DIFF")
        self.assertIn("OnCalendar=*-*-01 19:03:00", content)

    def test_generate_cleanup_service(self):
        content = generate_cleanup_service(self.venv, self.dar_path)
        self.assertIn("cleanup", content)
        self.assertIn("ExecStart=/bin/bash -c", content)

    @patch("builtins.print")
    @patch("pathlib.Path.write_text")
    def test_write_unit_file(self, mock_write, mock_print):
        from dar_backup.dar_backup_systemd import write_unit_file
        path = Path("/tmp")
        write_unit_file(path, "test.service", "unit content")
        mock_write.assert_called_once()
        mock_print.assert_called_once_with("Generated test.service")

if __name__ == '__main__':
    unittest.main()
