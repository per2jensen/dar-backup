import io
import os
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import dar_backup.dar_backup as db


def test_iter_files_with_paths_from_xml_streams_paths(tmp_path):
    xml = """<?xml version="1.0"?>
<DARArchive>
  <Directory name="dirA">
    <File name="a.txt" size="123"/>
    <Directory name="nested">
      <File name="b.bin" size="456"/>
    </Directory>
  </Directory>
  <File name="root.log" size="78"/>
</DARArchive>
"""
    xml_path = tmp_path / "list.xml"
    xml_path.write_text(xml, encoding="utf-8")

    result = list(db.iter_files_with_paths_from_xml(str(xml_path)))

    assert ("dirA/a.txt", "123") in result
    assert ("dirA/nested/b.bin", "456") in result
    assert ("root.log", "78") in result


def test_filter_restoretest_candidates_logs_excluded(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(db, "logger", logger)

    config = SimpleNamespace(
        restoretest_exclude_prefixes=["skip/"],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
    )
    files = ["keep/file.txt", "skip/file.txt"]

    result = db.filter_restoretest_candidates(files, config)

    assert result == ["keep/file.txt"]
    assert any("excluded 1" in call.args[0] for call in logger.debug.call_args_list)


def test_select_restoretest_samples_logs_summary(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(db, "logger", logger)

    config = SimpleNamespace(
        min_size_verification_mb=0,
        max_size_verification_mb=10,
        restoretest_exclude_prefixes=["skip/"],
        restoretest_exclude_suffixes=[],
        restoretest_exclude_regex=None,
    )
    backed_up_files = [
        ("keep/file1.txt", "1 Mio"),
        ("skip/file2.txt", "1 Mio"),
        ("keep/file3.txt", "1 Mio"),
    ]

    result = db.select_restoretest_samples(backed_up_files, config, sample_size=5)

    assert "keep/file1.txt" in result
    assert "keep/file3.txt" in result
    assert any("excluded 1 of 3" in call.args[0] for call in logger.debug.call_args_list)
    assert any("selecting all" in call.args[0] for call in logger.debug.call_args_list)


def test_create_backup_command_requires_base_for_diff():
    with pytest.raises(ValueError, match="Base backup is required"):
        db.create_backup_command(
            "DIFF",
            "/tmp/backup",
            "/tmp/.darrc",
            "/tmp/definition.dcf",
            None,
        )


def test_validate_required_directories_missing(tmp_path):
    config = SimpleNamespace(
        backup_dir=str(tmp_path / "missing_backups"),
        backup_d_dir=str(tmp_path / "missing_backup_d"),
        test_restore_dir=str(tmp_path / "missing_restore"),
    )

    with pytest.raises(RuntimeError, match="Required directories missing"):
        db.validate_required_directories(config)


def test_list_definitions_requires_dir(tmp_path):
    with pytest.raises(RuntimeError, match="BACKUP.D_DIR does not exist"):
        db.list_definitions(str(tmp_path / "missing_backup_d"))


def test_preflight_reports_missing_paths_and_permissions(monkeypatch, tmp_path, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    config = SimpleNamespace(
        backup_dir=None,
        backup_d_dir=str(tmp_path / "missing_backup_d"),
        test_restore_dir=str(tmp_path / "restore"),
        logfile_location=str(log_dir / "dar-backup.log"),
        par2_enabled=False,
    )
    args = SimpleNamespace(backup_definition=None)

    def fake_isdir(path):
        if path == str(tmp_path / "missing_backup_d"):
            return False
        return True

    def fake_access(path, mode):
        if path == str(tmp_path / "restore"):
            return False
        return True

    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path).endswith(".dar-backup-preflight"):
            raise OSError("nope")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(db.os.path, "isdir", fake_isdir)
    monkeypatch.setattr(db.os, "access", fake_access)
    monkeypatch.setattr(db.shutil, "which", lambda cmd: f"/bin/{cmd}")
    monkeypatch.setattr(db.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr("builtins.open", fake_open)

    ok = db.preflight_check(args, config)
    assert ok is False

    out = capsys.readouterr().out
    assert "BACKUP_DIR is not set" in out
    assert "BACKUP.D_DIR does not exist" in out
    assert "TEST_RESTORE_DIR is not writable" in out
    assert "Cannot write to TEST_RESTORE_DIR" in out


def test_preflight_reports_missing_binaries(tmp_path, monkeypatch, capsys):
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    log_dir = tmp_path / "logs"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()
    log_dir.mkdir()

    config = SimpleNamespace(
        backup_dir=str(backup_dir),
        backup_d_dir=str(backup_d_dir),
        test_restore_dir=str(test_restore_dir),
        logfile_location=str(log_dir / "dar-backup.log"),
        par2_enabled=True,
    )
    args = SimpleNamespace(backup_definition=None)

    monkeypatch.setattr(db.shutil, "which", lambda cmd: None)

    ok = db.preflight_check(args, config)
    assert ok is False

    out = capsys.readouterr().out
    assert "Binary not found on PATH: dar" in out
    assert "Binary not found on PATH: par2" in out


def test_preflight_reports_version_failures(tmp_path, monkeypatch, capsys):
    backup_dir = tmp_path / "backups"
    backup_d_dir = tmp_path / "backup.d"
    test_restore_dir = tmp_path / "restore"
    log_dir = tmp_path / "logs"
    backup_dir.mkdir()
    backup_d_dir.mkdir()
    test_restore_dir.mkdir()
    log_dir.mkdir()

    config = SimpleNamespace(
        backup_dir=str(backup_dir),
        backup_d_dir=str(backup_d_dir),
        test_restore_dir=str(test_restore_dir),
        logfile_location=str(log_dir / "dar-backup.log"),
        par2_enabled=True,
    )
    args = SimpleNamespace(backup_definition=None)

    monkeypatch.setattr(db.shutil, "which", lambda cmd: f"/bin/{cmd}")

    def fake_run(*args, **kwargs):
        raise Exception("boom")

    monkeypatch.setattr(db.subprocess, "run", fake_run)

    ok = db.preflight_check(args, config)
    assert ok is False

    out = capsys.readouterr().out
    assert "Failed to run 'dar --version'" in out
    assert "Failed to run 'par2 --version'" in out


def test_verify_runner_exception_propagates(tmp_path, monkeypatch):
    args = SimpleNamespace(verbose=False, do_not_compare=True, darrc="dummy")
    config = SimpleNamespace(
        test_restore_dir=str(tmp_path / "restore"),
        logfile_location=str(tmp_path / "dar-backup.log"),
        command_timeout_secs=5,
        backup_dir=str(tmp_path),
        min_size_verification_mb=0,
        max_size_verification_mb=1,
        no_files_verification=1,
    )

    runner = SimpleNamespace(run=MagicMock(side_effect=RuntimeError("boom")))
    monkeypatch.setattr(db, "runner", runner)
    monkeypatch.setattr(db, "logger", MagicMock())

    with pytest.raises(RuntimeError, match="boom"):
        db.verify(args, "archive", str(tmp_path / "def.dcf"), config)


def test_verify_restore_dir_create_error(tmp_path, monkeypatch):
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc="dummy")
    config = SimpleNamespace(
        test_restore_dir=str(tmp_path / "restore"),
        logfile_location=str(tmp_path / "dar-backup.log"),
        command_timeout_secs=5,
        backup_dir=str(tmp_path),
        min_size_verification_mb=0,
        max_size_verification_mb=10,
        no_files_verification=1,
    )
    backup_definition = tmp_path / "definition.dcf"
    backup_definition.write_text("-R /\n")

    runner = SimpleNamespace(run=MagicMock(return_value=SimpleNamespace(returncode=0)))
    monkeypatch.setattr(db, "runner", runner)
    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db, "get_backed_up_files", lambda *a, **k: [("/file.txt", "1 Mio")])
    monkeypatch.setattr(db.os, "makedirs", MagicMock(side_effect=OSError("nope")))

    with pytest.raises(db.BackupError, match="Cannot create restore directory"):
        db.verify(args, "archive", str(backup_definition), config)


def test_verify_restore_command_nonzero_raises(tmp_path, monkeypatch):
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc="dummy")
    config = SimpleNamespace(
        test_restore_dir=str(tmp_path / "restore"),
        logfile_location=str(tmp_path / "dar-backup.log"),
        command_timeout_secs=5,
        backup_dir=str(tmp_path),
        min_size_verification_mb=0,
        max_size_verification_mb=10,
        no_files_verification=1,
    )
    backup_definition = tmp_path / "definition.dcf"
    backup_definition.write_text("-R /\n")

    runner = SimpleNamespace(
        run=MagicMock(
            side_effect=[
                SimpleNamespace(returncode=0),
                SimpleNamespace(returncode=1, stdout="", stderr=""),
            ]
        )
    )
    monkeypatch.setattr(db, "runner", runner)
    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db, "get_backed_up_files", lambda *a, **k: [("/file.txt", "1 Mio")])

    with pytest.raises(Exception):
        db.verify(args, "archive", str(backup_definition), config)


def test_get_backed_up_files_subprocess_success(monkeypatch, tmp_path):
    xml = """<!DOCTYPE foo>
<DARArchive>
  <Directory name="dirA">
    <File name="a.txt" size="123"/>
  </Directory>
  <File name="root.txt" size="1"/>
</DARArchive>
"""

    class FakeProcess:
        def __init__(self, text):
            self.stdout = io.StringIO(text)
            self.stderr = None
            self.returncode = 0

        def wait(self, timeout=None):
            return None

    fake_process = FakeProcess(xml)

    monkeypatch.setattr(db, "runner", None)
    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db.subprocess, "Popen", lambda *a, **k: fake_process)

    files = list(db.get_backed_up_files("archive", str(tmp_path)))

    assert ("dirA/a.txt", "123") in files
    assert ("root.txt", "1") in files


def test_get_backed_up_files_subprocess_remove_warns(monkeypatch, tmp_path):
    xml = "<DARArchive><File name=\"root.txt\" size=\"1\"/></DARArchive>\n"
    temp_holder = {}
    real_named_temp = tempfile.NamedTemporaryFile
    real_remove = os.remove

    def fake_named_temp(*args, **kwargs):
        kwargs["dir"] = tmp_path
        tmp = real_named_temp(*args, **kwargs)
        temp_holder["path"] = tmp.name
        return tmp

    class FakeProcess:
        def __init__(self, text):
            self.stdout = io.StringIO(text)
            self.stderr = io.StringIO("boom\n")
            self.returncode = 1

        def wait(self, timeout=None):
            return None

    fake_process = FakeProcess(xml)

    def fake_remove(path):
        if path == temp_holder.get("path"):
            raise OSError("nope")
        return real_remove(path)

    monkeypatch.setattr(db, "runner", None)
    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db.tempfile, "NamedTemporaryFile", fake_named_temp)
    monkeypatch.setattr(db.os, "remove", fake_remove)
    monkeypatch.setattr(db.subprocess, "Popen", lambda *a, **k: fake_process)

    with pytest.raises(RuntimeError, match="Unexpected error listing backed up files"):
        db.get_backed_up_files("archive", str(tmp_path))

    assert db.logger.warning.called

    path = temp_holder.get("path")
    if path and os.path.exists(path):
        real_remove(path)


def test_list_contents_subprocess_success(monkeypatch, tmp_path, capsys):
    log_path = tmp_path / "command.log"
    handler = SimpleNamespace(baseFilename=str(log_path))
    command_logger = SimpleNamespace(handlers=[handler])
    error_logger = MagicMock()

    def fake_get_logger(command_output_logger=False):
        return command_logger if command_output_logger else error_logger

    class FakeProcess:
        def __init__(self, stdout_bytes, stderr_bytes, returncode=0):
            self.stdout = io.BytesIO(stdout_bytes)
            self.stderr = io.BytesIO(stderr_bytes)
            self.returncode = returncode

        def wait(self):
            return None

    stdout_bytes = b"[Saved] file1\n[--- REMOVED ENTRY ----] file2\n"
    stderr_bytes = b"abcdef"

    monkeypatch.setattr(db, "runner", SimpleNamespace(default_capture_limit_bytes=4))
    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db, "get_logger", fake_get_logger)
    monkeypatch.setattr(
        db.subprocess,
        "Popen",
        lambda *a, **k: FakeProcess(stdout_bytes, stderr_bytes, returncode=0),
    )

    db.list_contents("archive", str(tmp_path))

    out = capsys.readouterr().out
    assert "[Saved] file1" in out
    assert "[--- REMOVED ENTRY ----] file2" in out
    assert "COMMAND:" in log_path.read_text(encoding="utf-8", errors="replace")


def test_list_contents_subprocess_error(monkeypatch, tmp_path):
    log_path = tmp_path / "command.log"
    handler = SimpleNamespace(baseFilename=str(log_path))
    command_logger = SimpleNamespace(handlers=[handler])
    error_logger = MagicMock()

    def fake_get_logger(command_output_logger=False):
        return command_logger if command_output_logger else error_logger

    class FakeProcess:
        def __init__(self, stdout_bytes, returncode=1):
            self.stdout = io.BytesIO(stdout_bytes)
            self.stderr = None
            self.returncode = returncode

        def wait(self):
            return None

    monkeypatch.setattr(db, "runner", SimpleNamespace(default_capture_limit_bytes="bad"))
    monkeypatch.setattr(db, "logger", None)
    monkeypatch.setattr(db, "get_logger", fake_get_logger)
    monkeypatch.setattr(
        db.subprocess,
        "Popen",
        lambda *a, **k: FakeProcess(b"", returncode=1),
    )

    with pytest.raises(RuntimeError, match="Unexpected error listing contents"):
        db.list_contents("archive", str(tmp_path))

    assert error_logger.error.called


def test_perform_backup_alternate_reference_missing(monkeypatch, tmp_path):
    backup_d_dir = tmp_path / "backup.d"
    backup_dir = tmp_path / "backups"
    backup_d_dir.mkdir()
    backup_dir.mkdir()
    (backup_d_dir / "test.dcf").write_text("-R /\n")

    args = SimpleNamespace(
        backup_definition="test.dcf",
        alternate_reference_archive="missing_archive",
        darrc="dummy",
    )
    config = SimpleNamespace(backup_d_dir=str(backup_d_dir), backup_dir=str(backup_dir))

    monkeypatch.setattr(db, "logger", MagicMock())
    monkeypatch.setattr(db, "send_discord_message", MagicMock(return_value=True))

    results = db.perform_backup(args, config, "DIFF")

    assert any("Alternate reference archive" in msg for msg, _ in results)


def test_validate_slice_sequence_empty_list():
    with pytest.raises(RuntimeError, match="No dar slices found"):
        db._validate_slice_sequence([], "archive")


def test_get_par2_ratio_incr_override():
    par2_config = {"par2_ratio_incr": 7}
    assert db._get_par2_ratio("INCR", par2_config, 3) == 7


def test_generate_par2_files_par2_disabled(monkeypatch, tmp_path):
    class DummyConfig:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
            self.error_correction_percent = 5
            self.command_timeout_secs = 1

        def get_par2_config(self, backup_definition=None):
            return {"par2_enabled": False}

    config = DummyConfig(str(tmp_path))
    args = SimpleNamespace()

    monkeypatch.setattr(db, "runner", MagicMock())
    monkeypatch.setattr(db, "logger", MagicMock())

    db.generate_par2_files("example_FULL_2025-01-01", config, args, backup_definition="example")

    db.runner.run.assert_not_called()


def test_generate_par2_files_verify_failure(monkeypatch, tmp_path):
    (tmp_path / "example_FULL_2025-01-01.1.dar").write_text("")

    class DummyConfig:
        def __init__(self, backup_dir):
            self.backup_dir = backup_dir
            self.error_correction_percent = 5
            self.command_timeout_secs = 1

        def get_par2_config(self, backup_definition=None):
            return {"par2_enabled": True, "par2_run_verify": True}

    config = DummyConfig(str(tmp_path))
    args = SimpleNamespace(dar_version="1.0")

    monkeypatch.setattr(
        db,
        "runner",
        MagicMock(
            run=MagicMock(
                side_effect=[
                    SimpleNamespace(returncode=0),
                    SimpleNamespace(returncode=1),
                ]
            )
        ),
    )
    monkeypatch.setattr(db, "logger", MagicMock())

    with pytest.raises(subprocess.CalledProcessError):
        db.generate_par2_files("example_FULL_2025-01-01", config, args, backup_definition="example")


def test_filter_darrc_file_cleanup_on_error(monkeypatch, tmp_path):
    input_path = tmp_path / "input.darrc"
    input_path.write_text("-vt\n-foo\n")

    monkeypatch.setattr(db.os.path, "expanduser", lambda _: str(tmp_path))
    monkeypatch.setattr(db.os, "chmod", MagicMock(side_effect=OSError("nope")))

    with pytest.raises(RuntimeError, match="Error filtering .darrc file"):
        db.filter_darrc_file(str(input_path))

    leftover = [p for p in tmp_path.iterdir() if p.name.startswith("filtered_darrc_")]
    assert not leftover


def test_show_examples_prints_output(capsys):
    db.show_examples()
    out = capsys.readouterr().out
    assert "FULL back of all backup definitions" in out
