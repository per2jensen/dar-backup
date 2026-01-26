import unittest
from unittest.mock import patch
from pathlib import Path
import os
import sys
from sys import path as path

# Add src directory to path
path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.dar_backup_systemd import (
    generate_service,
    generate_timer,
    generate_cleanup_service,
    build_exec_command,
    enable_and_start_unit,
    FLAGS
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




from dar_backup.dar_backup_systemd import write_unit_files
from unittest.mock import MagicMock

def test_write_unit_files_triggers_enable_and_start(monkeypatch, tmp_path):
    venv = tmp_path / "venv"
    venv.mkdir()
    dar_path = "/usr/local/bin"

    mock_run = MagicMock()
    monkeypatch.setattr("dar_backup.dar_backup_systemd.subprocess.run", mock_run)

    # Optional: override Path.home() to avoid writing into ~/.config
    monkeypatch.setattr("dar_backup.dar_backup_systemd.Path.home", lambda: tmp_path)

    write_unit_files(str(venv), dar_path, install=True)

    calls = [call.args[0] for call in mock_run.call_args_list]

    assert ["systemctl", "--user", "enable", "dar-full-backup.timer"] in calls
    assert ["systemctl", "--user", "start", "dar-cleanup.timer"] in calls
    assert ["systemctl", "--user", "daemon-reexec"] in calls
    assert ["systemctl", "--user", "daemon-reload"] in calls


def test_enable_and_start_unit_runs_systemctl(monkeypatch):
    calls = []

    def fake_run(cmd, check=False, **kwargs):
        calls.append((cmd, check))

    monkeypatch.setattr("dar_backup.dar_backup_systemd.subprocess.run", fake_run)

    enable_and_start_unit("dar-full-backup.timer")

    assert calls == [
        (["systemctl", "--user", "enable", "dar-full-backup.timer"], False),
        (["systemctl", "--user", "start", "dar-full-backup.timer"], False),
    ]


def test_write_unit_files_no_install_writes_to_cwd(monkeypatch, tmp_path):
    written = []

    def fake_write_unit_file(path, filename, content):
        written.append((path, filename, content))

    monkeypatch.setattr("dar_backup.dar_backup_systemd.write_unit_file", fake_write_unit_file)
    monkeypatch.setattr("dar_backup.dar_backup_systemd.Path.cwd", lambda: tmp_path)
    monkeypatch.setattr("dar_backup.dar_backup_systemd.subprocess.run", MagicMock())

    write_unit_files("/fake/venv", None, install=False)

    assert len(written) == (len(FLAGS) * 2 + 2)
    assert all(path == tmp_path for path, _, _ in written)
    names = {name for _, name, _ in written}
    assert "dar-full-backup.service" in names
    assert "dar-full-backup.timer" in names
    assert "dar-diff-backup.service" in names
    assert "dar-incr-backup.timer" in names
    assert "dar-cleanup.service" in names
    assert "dar-cleanup.timer" in names

    full_service = next(content for _, name, content in written if name == "dar-full-backup.service")
    assert ". /fake/venv/bin/activate" in full_service
    assert "PATH=" not in full_service


def test_main_passes_args_to_write_unit_files(monkeypatch):
    calls = []

    def fake_write_unit_files(venv, dar_path, install=False):
        calls.append((venv, dar_path, install))

    monkeypatch.setattr("dar_backup.dar_backup_systemd.write_unit_files", fake_write_unit_files)
    monkeypatch.setattr(sys, "argv", ["prog", "--venv", "/opt/venv", "--dar-path", "/opt/dar", "--install"])

    from dar_backup.dar_backup_systemd import main as systemd_main

    systemd_main()

    assert calls == [("/opt/venv", "/opt/dar", True)]


if __name__ == '__main__':
    unittest.main()
