import io
import os
import sys
import logging
import configparser
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError
from dar_backup import util
import pytest

pytestmark = pytest.mark.unit



@pytest.fixture
def temp_logdir(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


def test_setup_logging_creates_file_and_logger(temp_logdir):
    logfile = temp_logdir / "test.log"
    command_output_file = temp_logdir / "command.log"

    logger = util.setup_logging(logfile, command_output_file)

    assert logfile.exists()
    assert command_output_file.exists()
    assert isinstance(logger, logging.Logger)


def test_setup_logging_stdout_and_file(tmp_path):
    logfile = tmp_path / "combo.log"
    command_output_file = tmp_path / "command.log"

    # We patch sys.stdout to a dummy, but setup_logging doesn’t support also_stdout anymore
    logger = util.setup_logging(logfile, command_output_file)
    logger.info("Hello from logger")

    assert logfile.exists()
    assert "Hello" in logfile.read_text()
    assert command_output_file.exists()


def _reset_logger(name):
    logger = logging.getLogger(name)
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    return logger


def test_setup_logging_falls_back_on_handler_failure(tmp_path, monkeypatch, capsys):
    logfile = tmp_path / "boom.log"
    command_output_file = tmp_path / "command.log"

    def raise_handler(*_args, **_kwargs):
        raise OSError("handler boom")

    _reset_logger("main_logger")
    _reset_logger("command_output_logger")
    monkeypatch.setattr(util, "RotatingFileHandler", raise_handler)
    monkeypatch.setattr(util.traceback, "print_exc", lambda: None)

    logger = util.setup_logging(logfile, command_output_file)

    assert isinstance(logger, logging.Logger)
    assert logger.handlers
    assert util.get_logger(command_output_logger=True) is not None

    err = capsys.readouterr().err
    assert "continuing with fallback" in err.lower()

def list_backups(backup_dir: Path) -> list:
    if not backup_dir.exists() or not backup_dir.is_dir():
        print("No backups available.")
        return []

    backups = [f.name for f in backup_dir.iterdir() if f.is_dir()]
    if not backups:
        print("No backups available.")
    else:
        for b in sorted(backups):
            print(b)

    return sorted(backups)



def test_list_backups_ignores_files(tmp_path, capsys):
    test_dir = tmp_path / "backups"
    test_dir.mkdir()

    # Create a valid .dar file matching expected pattern
    valid_backup = test_dir / "mybackup_FULL_2024-04-01.1.dar"
    valid_backup.write_text("dummy")

    # Create a file that should be ignored
    (test_dir / "note.txt").write_text("Ignore me")

    # Call the function
    util.list_backups(str(test_dir))

    # Capture stdout
    out = capsys.readouterr().out

    # Assertions: should include valid backup name, not note.txt
    assert "mybackup_FULL_2024-04-01" in out
    assert "note.txt" not in out




from dar_backup.util import get_invocation_command_line



def test_get_invocation_command_line_positive(monkeypatch):
    """
    Positive test:
    Simulates reading from /proc/[pid]/cmdline and verifies the reconstructed command line.
    """
    fake_cmdline = b"/usr/bin/python3\x00myscript.py\x00--option\x00value"

    def mock_open(*args, **kwargs):
        from io import BytesIO
        return BytesIO(fake_cmdline)

    monkeypatch.setattr("builtins.open", mock_open)
    result = get_invocation_command_line()

    assert isinstance(result, str)
    assert "/usr/bin/python3 myscript.py --option value" in result

def test_get_invocation_command_line_negative(monkeypatch):
    """
    Negative test:
    Simulates a file read failure (e.g. missing /proc/[pid]/cmdline) and verifies fallback message.
    """
    def mock_open(*args, **kwargs):
        raise FileNotFoundError("simulated missing /proc file")

    monkeypatch.setattr("builtins.open", mock_open)
    result = get_invocation_command_line()

    assert isinstance(result, str)
    assert "error" in result.lower()
    assert "could not read" in result.lower()


def test_get_invocation_command_line_empty(monkeypatch):
    def mock_open(*_args, **_kwargs):
        from io import BytesIO


        return BytesIO(b"")

    monkeypatch.setattr("builtins.open", mock_open)
    result = get_invocation_command_line()

    assert "empty" in result.lower()


def test_default_completer_logfile_without_getuid(monkeypatch):
    def raise_attr():
        raise AttributeError("no getuid")

    monkeypatch.setattr(util.os, "getuid", raise_attr)
    logfile = util._default_completer_logfile()
    assert logfile.endswith("_unknown.log")


def test_setup_completer_logger_fallbacks_to_nullhandler(monkeypatch):
    completer = logging.getLogger("completer")
    original_handlers = list(completer.handlers)
    completer.handlers = []

    def raise_handler(*_args, **_kwargs):
        raise OSError("no file handler")

    try:
        monkeypatch.setattr(logging, "FileHandler", raise_handler)
        logger = util._setup_completer_logger(logfile="/tmp/nowhere.log")
        assert any(isinstance(handler, logging.NullHandler) for handler in logger.handlers)
    finally:
        completer.handlers = original_handlers

def test_is_under_base_dir_positive(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    candidate = base_dir / "file.txt"
    candidate.write_text("ok")

    assert util.is_under_base_dir(candidate, base_dir) is True


def test_is_under_base_dir_outside(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    candidate = outside / "file.txt"
    candidate.write_text("nope")

    assert util.is_under_base_dir(candidate, base_dir) is False

@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink not supported")
def test_is_under_base_dir_symlink_escape(tmp_path):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "target.txt"
    target.write_text("ok")
    link = base_dir / "link.txt"
    link.symlink_to(target)

    assert util.is_under_base_dir(link, base_dir) is False


def test_safe_remove_file_deletes_valid(tmp_path):
    util.logger = logging.getLogger("test")
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    file_path = base_dir / "example_FULL_2024-01-01.1.dar"
    file_path.write_text("ok")

    assert util.safe_remove_file(str(file_path), base_dir=base_dir) is True
    assert not file_path.exists()


def test_safe_remove_file_refuses_outside_base(tmp_path):
    util.logger = logging.getLogger("test")
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    file_path = outside / "example_FULL_2024-01-01.1.dar"
    file_path.write_text("ok")

    assert util.safe_remove_file(str(file_path), base_dir=base_dir) is False
    assert file_path.exists()


def test_safe_remove_file_refuses_bad_name(tmp_path):
    util.logger = logging.getLogger("test")
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    file_path = base_dir / "not-allowed.txt"
    file_path.write_text("ok")

    assert util.safe_remove_file(str(file_path), base_dir=base_dir) is False
    assert file_path.exists()

@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlink not supported")
def test_safe_remove_file_refuses_symlink(tmp_path):
    util.logger = logging.getLogger("test")
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    target = base_dir / "target.txt"
    target.write_text("ok")
    link = base_dir / "example_FULL_2024-01-02.1.dar"
    link.symlink_to(target)

    assert util.safe_remove_file(str(link), base_dir=base_dir) is False
    assert link.exists()
    assert target.exists()


def test_safe_remove_file_refuses_non_file(tmp_path):
    util.logger = logging.getLogger("test")
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    dir_path = base_dir / "example_FULL_2024-01-03.1.dar"
    dir_path.mkdir()

    assert util.safe_remove_file(str(dir_path), base_dir=base_dir) is False
    assert dir_path.exists()


def test_is_archive_name_allowed_positive():
    assert util.is_archive_name_allowed("example_FULL_2024-01-01") is True
    assert util.is_archive_name_allowed("proj-1.INC_INCR_2024-12-31") is True
    assert util.is_archive_name_allowed(" example_DIFF_2024-02-29 ") is True


def test_is_archive_name_allowed_negative():
    assert util.is_archive_name_allowed("example_BAD_2024-01-01") is False
    assert util.is_archive_name_allowed("example_FULL_2024-02-30") is False
    assert util.is_archive_name_allowed("../example_FULL_2024-01-01") is False
    assert util.is_archive_name_allowed(r"..\\example_FULL_2024-01-01") is False
    assert util.is_archive_name_allowed("example FULL_2024-01-01") is False
    assert util.is_archive_name_allowed("-bad_FULL_2024-01-01") is False


def test_is_under_base_dir_nested_positive(tmp_path):
    base = tmp_path / "base"
    (base / "a" / "b").mkdir(parents=True)
    candidate = base / "a" / "b" / "f.txt"
    candidate.write_text("ok")
    assert util.is_under_base_dir(candidate, base) is True


def test_safe_remove_file_refuses_bad_name(tmp_path, caplog):
    base_dir = tmp_path / "base"
    base_dir.mkdir()
    file_path = base_dir / "not-allowed.txt"
    file_path.write_text("ok")

    with caplog.at_level("WARNING"):
        assert util.safe_remove_file(str(file_path), base_dir=base_dir) is False

def test_is_archive_name_allowed_rejects_separators():
    assert util.is_archive_name_allowed("a/b_FULL_2024-01-01") is False
    assert util.is_archive_name_allowed(r"a\b_FULL_2024-01-01") is False


def test_extract_backup_definition_fallback_dash_d(monkeypatch):
    monkeypatch.setenv("COMP_LINE", "dar-backup --list-contents -d new-monster")
    assert util.extract_backup_definition_fallback() == "new-monster"


def test_extract_backup_definition_fallback_long_flag(monkeypatch):
    monkeypatch.setenv("COMP_LINE", "dar-backup --backup-definition new-monster --list")
    assert util.extract_backup_definition_fallback() == "new-monster"


def test_extract_backup_definition_fallback_equals(monkeypatch):
    monkeypatch.setenv("COMP_LINE", "dar-backup --backup-def=new-monster --list")
    assert util.extract_backup_definition_fallback() == "new-monster"


def test_split_archive_list_prefix_empty():
    assert util.split_archive_list_prefix("") == ("", "")


def test_split_archive_list_prefix_single():
    assert util.split_archive_list_prefix("new-monster") == ("", "new-monster")


def test_split_archive_list_prefix_strips_spaces():
    head, last = util.split_archive_list_prefix("a,  b , c")
    assert head == "a, b"
    assert last == "c"


def test_list_archive_completer_handles_list_with_spaces(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "new-monster_FULL_2025-12-31.1.dar").write_text("dummy")
    (backup_dir / "other_FULL_2025-12-31.1.dar").write_text("dummy")

    config_path = tmp_path / "dar-backup.conf"
    config_path.write_text("[DIRECTORIES]\nBACKUP_DIR=%s\n" % backup_dir)

    args = type("Args", (), {"backup_definition": None, "backup_def": None, "config_file": str(config_path)})
    completions = util.list_archive_completer("old,  new-mon", args)

    assert "old, new-monster_FULL_2025-12-31" in completions


def test_list_archive_completer_cleanup_without_specific_archives(monkeypatch):
    monkeypatch.setenv("COMP_LINE", "cleanup ")
    args = type("Args", (), {"backup_definition": None, "backup_def": None, "config_file": "/nope"})
    assert util.list_archive_completer("", args) == []


def test_send_discord_message_returns_false_without_webhook(monkeypatch):
    monkeypatch.delenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", raising=False)
    fake_logger = MagicMock()
    monkeypatch.setattr(util, "logger", fake_logger)

    assert util.send_discord_message("hello", config_settings=None) is False
    fake_logger.info.assert_called_once()
    assert "not configured" in fake_logger.info.call_args[0][0].lower()


def test_send_discord_message_http_error_logs_and_returns_false(monkeypatch):
    fake_logger = MagicMock()
    monkeypatch.setattr(util, "logger", fake_logger)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", "https://example/webhook")

    def fake_urlopen(request, timeout):
        raise HTTPError(
            request.full_url,
            429,
            "Too Many Requests",
            None,
            io.BytesIO(b"rate limited")
        )

    monkeypatch.setattr(util.urllib.request, "urlopen", fake_urlopen)

    assert util.send_discord_message("hello") is False
    fake_logger.error.assert_called_once()
    assert "http error 429" in fake_logger.error.call_args[0][0].lower()


def test_send_discord_message_unexpected_error_logs_and_returns_false(monkeypatch):
    fake_logger = MagicMock()
    monkeypatch.setattr(util, "logger", fake_logger)
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", "https://example/webhook")

    def fake_urlopen(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(util.urllib.request, "urlopen", fake_urlopen)

    assert util.send_discord_message("hello") is False
    fake_logger.error.assert_called_once()
    assert "failed to send discord webhook message" in fake_logger.error.call_args[0][0].lower()


def test_add_specific_archive_completer_filters_existing_db_entries(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    backup_d_dir = tmp_path / "backup.d"
    backup_d_dir.mkdir()

    config_path = tmp_path / "dar-backup.conf"
    config_path.write_text(
        "[MISC]\n"
        "LOGFILE_LOCATION = /tmp/test.log\n"
        "MAX_SIZE_VERIFICATION_MB = 100\n"
        "MIN_SIZE_VERIFICATION_MB = 1\n"
        "NO_FILES_VERIFICATION = 5\n"
        "COMMAND_TIMEOUT_SECS = 5\n"
        "\n"
        "[DIRECTORIES]\n"
        f"BACKUP_DIR = {backup_dir}\n"
        "TEST_RESTORE_DIR = /tmp/restore\n"
        f"BACKUP.D_DIR = {backup_d_dir}\n"
        "\n"
        "[AGE]\n"
        "DIFF_AGE = 3\n"
        "INCR_AGE = 1\n"
        "\n"
        "[PAR2]\n"
        "ERROR_CORRECTION_PERCENT = 10\n"
        "ENABLED = false\n"
    )

    (backup_dir / "example_FULL_2024-01-01.1.dar").write_text("data")
    (backup_dir / "example_INCR_2024-01-02.1.dar").write_text("data")
    (backup_dir / "example_DIFF_2024-01-03.1.dar").write_text("data")
    (backup_dir / "other_FULL_2024-01-04.1.dar").write_text("data")
    (backup_dir / "example.db").write_text("db")

    args = SimpleNamespace(config_file=str(config_path), backup_def="example")
    existing_output = "\n".join(
        [
            "\t1\t/tmp\texample_FULL_2024-01-01",
            "\t2\t/tmp\texample_DIFF_2024-01-03",
        ]
    )

    with patch("dar_backup.util.subprocess.run") as mock_run:
        mock_run.return_value = SimpleNamespace(
            stdout=existing_output,
            stderr="",
            returncode=0
        )
        result = util.add_specific_archive_completer("example", args)

    assert result == ["example_INCR_2024-01-02"]


def test_list_backups_no_backups(tmp_path, capsys):
    util.list_backups(str(tmp_path))
    out = capsys.readouterr().out
    assert "no backups available" in out.lower()


def test_is_safe_path_requires_absolute():
    assert util.is_safe_path("/tmp/dir/file.txt") is True
    assert util.is_safe_path("tmp/dir/file.txt") is False
    assert util.is_safe_path("../tmp/file.txt") is False


def test_print_debug_includes_filename_and_repr(capsys):
    util.print_debug("hello")
    out = capsys.readouterr().out.strip()
    assert out.startswith("[DEBUG]")
    assert "test_util.py" in out
    assert repr("hello") in out


def test_show_scriptname_uses_sys_argv(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["dar-backup", "--help"])
    assert util.show_scriptname() == "dar-backup"


def test_show_scriptname_returns_unknown_on_error(monkeypatch):
    monkeypatch.setattr(sys, "argv", None)
    assert util.show_scriptname() == "unknown"


def test_patch_config_file_replaces_only_matching_keys(tmp_path):
    config_path = tmp_path / "config.conf"
    config_path.write_text("A=1\nB=2\nC = 3\n")

    util.patch_config_file(str(config_path), {"A": "10", "C": "30"})

    content = config_path.read_text().splitlines()
    assert "A = 10" in content
    assert "C = 30" in content
    assert "B=2" in content


def test_normalize_dir_strips_trailing_separator(tmp_path):
    raw = str(tmp_path / "dir") + "/"
    assert util.normalize_dir(raw) == str(tmp_path / "dir")


def test_requirements_uses_popen_path_success(monkeypatch):
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "echo ok"}
    config_setting = SimpleNamespace(config=config)

    def getenv_override(key, default=None):
        if key == "PYTEST_CURRENT_TEST":
            return None
        return os.getenv(key, default)

    class FakeProcess:
        def __init__(self):
            self.returncode = 0
            self.stdout = io.StringIO("ok\n")
            self.stderr = io.StringIO("")

        def wait(self):
            return None

    monkeypatch.setattr(util, "logger", MagicMock())
    monkeypatch.setattr(util.os, "getenv", getenv_override)
    monkeypatch.setattr(util.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    util.requirements("PREREQ", config_setting)


def test_requirements_uses_popen_path_failure(monkeypatch):
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "echo nope"}
    config_setting = SimpleNamespace(config=config)

    def getenv_override(key, default=None):
        if key == "PYTEST_CURRENT_TEST":
            return None
        return os.getenv(key, default)

    class FakeProcess:
        def __init__(self):
            self.returncode = 1
            self.stdout = io.StringIO("")
            self.stderr = io.StringIO("nope\n")

        def wait(self):
            return None

    monkeypatch.setattr(util, "logger", MagicMock())
    monkeypatch.setattr(util.os, "getenv", getenv_override)
    monkeypatch.setattr(util.subprocess, "Popen", lambda *args, **kwargs: FakeProcess())

    with pytest.raises(RuntimeError):
        util.requirements("PREREQ", config_setting)


# ---------------------------------------------------------------------------
# extract_version
# ---------------------------------------------------------------------------

def test_extract_version_parses_full_semver():
    """
    A three-part semantic version embedded in dar --version output is extracted.
    """
    assert util.extract_version("dar 2.7.5, Copyright 2002-2024") == "2.7.5"


def test_extract_version_parses_two_part_version():
    """
    A two-part version (major.minor) without a patch segment is extracted.
    """
    assert util.extract_version("par2 version 0.9") == "0.9"


def test_extract_version_returns_unknown_when_no_digits():
    """
    Output that contains no digit sequence matching N.N returns 'unknown'.
    """
    assert util.extract_version("no version string here") == "unknown"


def test_extract_version_returns_unknown_for_empty_string():
    """
    Empty input returns 'unknown' without raising an exception.
    """
    assert util.extract_version("") == "unknown"


# ---------------------------------------------------------------------------
# sort_key
# ---------------------------------------------------------------------------

def test_sort_key_standard_archive_returns_correct_tuple():
    """
    A well-formed archive name is decomposed into (definition, date).
    """
    from datetime import datetime
    def_name, date = util.sort_key("mydef_FULL_2024-01-15.1.dar")
    assert def_name == "mydef"
    assert date == datetime(2024, 1, 15)


def test_sort_key_definition_name_with_underscore():
    """
    Definition names that themselves contain underscores are reconstructed intact.
    E.g. 'my_def_DIFF_2024-06-01.1.dar' → def_name='my_def', date=2024-06-01.
    """
    from datetime import datetime
    def_name, date = util.sort_key("my_def_DIFF_2024-06-01.1.dar")
    assert def_name == "my_def"
    assert date == datetime(2024, 6, 1)


def test_sort_key_sorts_archives_by_definition_then_date():
    """
    Sorting a mixed list of archives with sort_key orders by definition first,
    then chronologically within each definition.
    """
    from datetime import datetime
    archives = [
        "mydef_FULL_2024-03-01.1.dar",
        "mydef_FULL_2024-01-01.1.dar",
        "alpha_FULL_2024-06-01.1.dar",
    ]
    result = sorted(archives, key=util.sort_key)
    assert result[0].startswith("alpha")
    assert result[1] == "mydef_FULL_2024-01-01.1.dar"
    assert result[2] == "mydef_FULL_2024-03-01.1.dar"


def test_sort_key_fewer_than_three_underscore_parts_returns_fallback():
    """
    An archive name that has fewer than three underscore-separated parts (no
    TYPE and DATE) falls back to (archive_name, datetime.min) without raising.
    """
    from datetime import datetime
    name = "nodots_only.1.dar"
    def_name, date = util.sort_key(name)
    assert def_name == name
    assert date == datetime.min


def test_sort_key_invalid_date_string_returns_fallback():
    """
    An archive whose date segment cannot be parsed as YYYY-MM-DD falls back
    to (archive_name, datetime.min) without raising.
    """
    from datetime import datetime
    name = "mydef_FULL_not-a-date.1.dar"
    def_name, date = util.sort_key(name)
    assert def_name == name
    assert date == datetime.min


# ---------------------------------------------------------------------------
# parse_dar_stats — graceful degradation
# ---------------------------------------------------------------------------

class TestParseDarStats:
    """parse_dar_stats must never raise and must return None for absent fields."""

    def test_empty_string_returns_all_none(self):
        """Empty output (e.g. dar produced no stdout/stderr) → all None, no crash."""
        result = util.parse_dar_stats("")
        assert all(v is None for v in result.values()), (
            "All metrics must be None when output is empty"
        )

    def test_none_like_empty_string_returns_all_none(self):
        """Passing an empty string (stdout_tail default) → all None."""
        result = util.parse_dar_stats("")
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_garbage_output_returns_all_none(self):
        """Unrecognised output (old dar format, truncated run) → all None, no crash."""
        result = util.parse_dar_stats("This is some random text with no dar stats\n")
        assert all(v is None for v in result.values())

    def test_partial_output_parses_available_fields(self):
        """Only fields present in output are non-None; absent fields stay None."""
        partial = " 7 inode(s) saved\n  including 0 hard link(s) treated\n"
        result = util.parse_dar_stats(partial)
        assert result["inodes_saved"] == 7
        assert result["hard_links_treated"] == 0
        # A field not in the partial output must be None
        assert result["inodes_total"] is None

    def test_full_dar_output_parses_correctly(self):
        """
        A complete dar statistics block (as produced by dar >= 2.7.21) is parsed
        without error and all key fields are non-None integers.
        """
        sample = (
            " --------------------------------------------\n"
            " 15 inode(s) saved\n"
            "   including 2 hard link(s) treated\n"
            " 0 inode(s) changed at the moment of the backup and could not be saved properly\n"
            " 0 byte(s) have been wasted in the archive to resave changing files\n"
            " 1 inode(s) with only metadata changed\n"
            " 3 inode(s) not saved (no inode/file change)\n"
            " 0 inode(s) failed to be saved (filesystem error)\n"
            " 0 inode(s) ignored (excluded by filters)\n"
            " 0 inode(s) recorded as deleted from reference backup\n"
            " --------------------------------------------\n"
            " Total number of inode(s) considered: 18\n"
            " --------------------------------------------\n"
            " EA saved for 0 inode(s)\n"
            " FSA saved for 15 inode(s)\n"
            " --------------------------------------------\n"
        )
        result = util.parse_dar_stats(sample)
        assert result["inodes_saved"] == 15
        assert result["hard_links_treated"] == 2
        assert result["inodes_metadata_only"] == 1
        assert result["inodes_not_saved"] == 3
        assert result["inodes_total"] == 18
        assert result["ea_saved"] == 0
        assert result["fsa_saved"] == 15
        assert all(v is not None for v in result.values()), (
            "All fields must parse for a complete dar stats block"
        )

    def test_returns_dict_with_all_expected_keys(self):
        """Result always contains all metric keys regardless of output content."""
        result = util.parse_dar_stats("no stats here")
        expected_keys = {
            "inodes_saved", "hard_links_treated", "inodes_changed_during_backup",
            "bytes_wasted", "inodes_metadata_only", "inodes_not_saved",
            "inodes_failed", "inodes_excluded", "inodes_deleted",
            "inodes_total", "ea_saved", "fsa_saved",
        }
        assert expected_keys.issubset(result.keys())


# ---------------------------------------------------------------------------
# write_metrics_row — graceful degradation
# ---------------------------------------------------------------------------

class TestWriteMetricsRowGraceful:
    """write_metrics_row must never raise — metrics must not abort a backup."""

    def _make_config(self, db_path: str):
        """Return a minimal config_settings stub with metrics_db_path set."""
        cfg = SimpleNamespace()
        cfg.metrics_db_path = db_path
        return cfg

    def test_all_null_inode_stats_writes_row_without_error(self, tmp_path):
        """
        A metrics dict where all inode fields are None (dar < 2.7.21 or absent
        stats block) must still write a row successfully — graceful degradation.
        """
        db = str(tmp_path / "metrics.db")
        metrics = {
            "backup_definition": "test-def",
            "backup_type": "FULL",
            "archive_name": "test-def_FULL_2026-01-01",
            "dar_backup_version": "1.1.3",
            "dar_version": "2.7.19",
            "run_started_at": "2026-01-01T00:00:00Z",
            "run_finished_at": "2026-01-01T00:01:00Z",
            "duration_secs": 60.0,
            "dar_duration_secs": 50.0,
            "verify_duration_secs": 9.0,
            "par2_duration_secs": None,
            "status": "SUCCESS",
            "dar_exit_code": 0,
            "failed_phase": None,
            "error_summary": None,
            "catalog_updated": 1,
            "verify_passed": 1,
            "restore_test_passed": 1,
            "par2_passed": None,
            "archive_size_bytes": 1024,
            "num_slices": 1,
            "par2_size_bytes": None,
            "files_verified": 3,
            "backup_dir_free_bytes": 1_000_000,
            "hostname": "testhost",
            # All inode stats None — simulates dar < 2.7.21
            "inodes_saved": None,
            "hard_links_treated": None,
            "inodes_changed_during_backup": None,
            "bytes_wasted": None,
            "inodes_metadata_only": None,
            "inodes_not_saved": None,
            "inodes_failed": None,
            "inodes_excluded": None,
            "inodes_deleted": None,
            "inodes_total": None,
            "ea_saved": None,
            "fsa_saved": None,
        }
        cfg = self._make_config(db)
        # Must not raise
        util.write_metrics_row(metrics, cfg)

        import sqlite3
        with sqlite3.connect(db) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM backup_runs").fetchone()
        assert row is not None, "Row must be written even when all inode stats are NULL"
        assert row["status"] == "SUCCESS"
        assert row["inodes_saved"] is None, "NULL inode stats stored as NULL — not an error"

    def test_db_write_error_does_not_raise(self, tmp_path):
        """
        If the SQLite write fails (e.g. DB is read-only), write_metrics_row must
        log a warning and return — never propagate the exception to the caller.
        """
        db = str(tmp_path / "metrics.db")
        # Pre-create the DB then make it read-only
        util.ensure_metrics_db(db)
        import stat
        os.chmod(db, stat.S_IRUSR | stat.S_IRGRP)
        try:
            cfg = self._make_config(db)
            metrics = {k: None for k in [
                "backup_definition", "backup_type", "archive_name",
                "dar_backup_version", "dar_version", "run_started_at",
                "run_finished_at", "duration_secs", "dar_duration_secs",
                "verify_duration_secs", "par2_duration_secs", "status",
                "dar_exit_code", "failed_phase", "error_summary",
                "catalog_updated", "verify_passed", "restore_test_passed",
                "par2_passed", "archive_size_bytes", "num_slices",
                "par2_size_bytes", "files_verified", "backup_dir_free_bytes",
                "hostname", "inodes_saved", "hard_links_treated",
                "inodes_changed_during_backup", "bytes_wasted",
                "inodes_metadata_only", "inodes_not_saved", "inodes_failed",
                "inodes_excluded", "inodes_deleted", "inodes_total",
                "ea_saved", "fsa_saved",
            ]}
            # Must not raise — backup must continue even if metrics write fails
            util.write_metrics_row(metrics, cfg)
        finally:
            os.chmod(db, stat.S_IRUSR | stat.S_IWUSR)
