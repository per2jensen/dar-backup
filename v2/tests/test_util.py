import io
import os
import sys
import logging
import configparser
import threading
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
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



def test_get_invocation_command_line_positive():
    """
    Reads /proc/self/cmdline for the current pytest process — no mock needed,
    the file always exists and is readable on Linux.
    """
    result = get_invocation_command_line()
    assert isinstance(result, str)
    assert result and not result.startswith("[error:")

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


def test_is_under_base_dir_nonexistent_base_logs_warning(tmp_path, caplog):
    """
    A base_dir that cannot be resolved (e.g. it no longer exists) must not silently
    return False indistinguishably from a genuine "outside the base dir" result — the
    resolution failure is security-relevant for safe_remove_file()'s containment check
    and must be logged.
    """
    base_dir = tmp_path / "does-not-exist"
    candidate = tmp_path / "does-not-exist" / "file.txt"

    with caplog.at_level("WARNING"):
        result = util.is_under_base_dir(candidate, base_dir)

    assert result is False
    assert any(str(base_dir) in r.message for r in caplog.records)


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


def test_send_discord_message_returns_false_without_webhook(monkeypatch, caplog):
    monkeypatch.delenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", raising=False)

    with caplog.at_level(logging.INFO):
        assert util.send_discord_message("hello", config_settings=None) is False

    assert any("not configured" in r.message.lower() for r in caplog.records)


def test_send_discord_message_http_error_logs_and_returns_false(monkeypatch, caplog):
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

    with caplog.at_level(logging.ERROR):
        assert util.send_discord_message("hello") is False

    assert any("http error 429" in r.message.lower() for r in caplog.records)


def test_send_discord_message_unexpected_error_logs_and_returns_false(monkeypatch, caplog):
    monkeypatch.setenv("DAR_BACKUP_DISCORD_WEBHOOK_URL", "https://example/webhook")

    def fake_urlopen(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(util.urllib.request, "urlopen", fake_urlopen)

    with caplog.at_level(logging.ERROR):
        assert util.send_discord_message("hello") is False

    assert any("failed to send discord webhook message" in r.message.lower() for r in caplog.records)


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


def test_patch_config_file_unwritable_directory_leaves_original_intact(tmp_path):
    """
    If the directory is not writable, mkstemp fails and the original file must
    be left completely intact — the atomic write guarantees no partial overwrite.
    """
    import stat
    config_path = tmp_path / "config.conf"
    original = "A=1\nB=2\n"
    config_path.write_text(original)

    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IXUSR)  # read + traverse, no write
    try:
        with pytest.raises(OSError):
            util.patch_config_file(str(config_path), {"A": "10"})
        assert config_path.read_text() == original
    finally:
        os.chmod(tmp_path, stat.S_IRWXU)


def test_normalize_dir_strips_trailing_separator(tmp_path):
    raw = str(tmp_path / "dir") + "/"
    assert util.normalize_dir(raw) == str(tmp_path / "dir")


def test_requirements_success_runs_real_command():
    """A zero-exit PREREQ command must complete without raising."""
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "echo ok"}
    config_setting = SimpleNamespace(config=config, command_timeout_secs=30)
    util.requirements("PREREQ", config_setting)


def test_requirements_failure_raises_on_nonzero_exit():
    """A non-zero-exit PREREQ command must raise RuntimeError."""
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "exit 1"}
    config_setting = SimpleNamespace(config=config, command_timeout_secs=30)
    with pytest.raises(RuntimeError):
        util.requirements("PREREQ", config_setting)


def test_requirements_timeout_kills_hanging_script():
    """A PREREQ script that exceeds command_timeout_secs must be killed and raise RuntimeError."""
    config = configparser.ConfigParser()
    config["PREREQ"] = {"001": "sleep 60"}
    config_setting = SimpleNamespace(config=config, command_timeout_secs=1)
    with pytest.raises(RuntimeError, match="timed out"):
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
            "run_id": None,
            "prereq_status": None,
            "postreq_status": None,
        }
        cfg = self._make_config(db)
        # Must not raise
        util.write_metrics_row(metrics, cfg)

        import sqlite3
        with closing(sqlite3.connect(db)) as conn:
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
                "run_id", "prereq_status", "postreq_status",
            ]}
            # Must not raise — backup must continue even if metrics write fails
            util.write_metrics_row(metrics, cfg)
        finally:
            os.chmod(db, stat.S_IRUSR | stat.S_IWUSR)


def test_list_backups_malformed_date_does_not_crash(tmp_path, capsys):
    """
    A .dar file whose name passes the regex filter but contains an out-of-range
    calendar date (month 13) must not crash list_backups.

    The sort key falls back to datetime.min so the entry still appears in output.
    """
    (tmp_path / "mybackup_FULL_2024-13-99.1.dar").write_text("x")
    (tmp_path / "mybackup_FULL_2024-01-01.1.dar").write_text("x")

    util.list_backups(str(tmp_path))

    out = capsys.readouterr().out
    assert "mybackup_FULL_2024-13-99" in out
    assert "mybackup_FULL_2024-01-01" in out


def test_list_backups_getsize_oserror_does_not_crash(tmp_path, capsys):
    """
    A broken symlink whose name matches the dar filename pattern causes
    os.path.getsize() to raise OSError (the symlink target does not exist).
    list_backups must skip the broken entry and continue without raising.
    """
    (tmp_path / "good_FULL_2024-01-01.1.dar").write_text("x")
    broken = tmp_path / "broken_FULL_2024-01-02.1.dar"
    broken.symlink_to("/nonexistent/target.1.dar")

    util.list_backups(str(tmp_path))

    out = capsys.readouterr().out
    assert "good_FULL_2024-01-01" in out
    assert "broken_FULL_2024-01-02" not in out


# ---------------------------------------------------------------------------
# compare_metadata unit tests
# ---------------------------------------------------------------------------

def _make_pair(tmp_path):
    """Return (source_path, restored_path) with identical content, mode, mtime."""
    src = tmp_path / "source.txt"
    rst = tmp_path / "restored.txt"
    src.write_text("data")
    rst.write_text("data")
    os.chmod(str(src), 0o644)
    os.chmod(str(rst), 0o644)
    src_stat = os.stat(str(src))
    os.utime(str(rst), ns=(src_stat.st_atime_ns, src_stat.st_mtime_ns))
    return str(src), str(rst)


def test_compare_metadata_permissions_mismatch_detected(tmp_path):
    """A permission difference between source and restored is reported."""
    src, rst = _make_pair(tmp_path)
    os.chmod(rst, 0o600)

    mismatches = util.compare_metadata(src, rst)

    assert len(mismatches) == 1
    assert "permission mismatch" in mismatches[0]


def test_compare_metadata_mtime_mismatch_detected(tmp_path):
    """An mtime difference between source and restored is reported."""
    src, rst = _make_pair(tmp_path)
    # nudge mtime by 1 second
    rst_stat = os.stat(rst)
    os.utime(rst, ns=(rst_stat.st_atime_ns, rst_stat.st_mtime_ns + 1_000_000_000))

    mismatches = util.compare_metadata(src, rst)

    assert len(mismatches) == 1
    assert "mtime mismatch" in mismatches[0]


def test_compare_metadata_uid_gid_not_checked_by_default(tmp_path, monkeypatch):
    """uid and gid differences are not reported when check_ownership=False (default).

    RESTORE_OWNERSHIP = no (the default) causes dar-backup to inject
    --comparison-field=ignore-owner so uid/gid are not restored.
    compare_metadata must not flag them as mismatches in that mode.
    """
    src, rst = _make_pair(tmp_path)

    src_stat = os.stat(src)
    fake_rst_stat = os.stat_result((
        src_stat.st_mode,
        src_stat.st_ino,
        src_stat.st_dev,
        src_stat.st_nlink,
        src_stat.st_uid + 1,   # uid differs — must be ignored
        src_stat.st_gid + 1,   # gid differs — must be ignored
        src_stat.st_size,
        src_stat.st_atime_ns,
        src_stat.st_mtime_ns,
        src_stat.st_ctime_ns,
    ))

    monkeypatch.setattr(os, "stat", lambda path, **kw: src_stat if path == src else fake_rst_stat)

    mismatches = util.compare_metadata(src, rst)  # check_ownership defaults to False

    assert not any("uid" in m for m in mismatches), "uid must not be checked when check_ownership=False"
    assert not any("gid" in m for m in mismatches), "gid must not be checked when check_ownership=False"


def test_compare_metadata_uid_gid_checked_when_ownership_preserved(tmp_path, monkeypatch):
    """uid and gid mismatches ARE reported when check_ownership=True.

    RESTORE_OWNERSHIP = yes causes dar to restore original uid/gid.
    compare_metadata must verify they were actually restored correctly.
    """
    src, rst = _make_pair(tmp_path)

    src_stat = os.stat(src)
    fake_rst_stat = os.stat_result((
        src_stat.st_mode,
        src_stat.st_ino,
        src_stat.st_dev,
        src_stat.st_nlink,
        src_stat.st_uid + 1,   # uid differs — must be detected
        src_stat.st_gid + 1,   # gid differs — must be detected
        src_stat.st_size,
        src_stat.st_atime_ns,
        src_stat.st_mtime_ns,
        src_stat.st_ctime_ns,
    ))

    monkeypatch.setattr(os, "stat", lambda path, **kw: src_stat if path == src else fake_rst_stat)

    mismatches = util.compare_metadata(src, rst, check_ownership=True)

    assert any("uid" in m for m in mismatches), "uid mismatch must be reported when check_ownership=True"
    assert any("gid" in m for m in mismatches), "gid mismatch must be reported when check_ownership=True"


def test_compare_metadata_uid_gid_match_no_false_positive(tmp_path, monkeypatch):
    """No uid/gid mismatch is reported when ownership matches, even with check_ownership=True."""
    src, rst = _make_pair(tmp_path)

    src_stat = os.stat(src)
    # Same uid/gid — no ownership mismatch
    monkeypatch.setattr(os, "stat", lambda path, **kw: src_stat)

    mismatches = util.compare_metadata(src, rst, check_ownership=True)

    assert not any("uid" in m for m in mismatches), "no uid mismatch expected when uid matches"
    assert not any("gid" in m for m in mismatches), "no gid mismatch expected when gid matches"


def test_compare_metadata_all_match_returns_empty(tmp_path):
    """No mismatches returns an empty list."""
    src, rst = _make_pair(tmp_path)

    mismatches = util.compare_metadata(src, rst)

    assert mismatches == []


# ---------------------------------------------------------------------------
# list_backups — locale robustness
# ---------------------------------------------------------------------------

def test_list_backups_formats_sizes_correctly(tmp_path, capsys):
    """list_backups() formats archive sizes with thousands separators."""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "homedir_FULL_2025-01-01.1.dar").write_bytes(b"x" * 1024 * 1024)
    (backup_dir / "homedir_DIFF_2025-02-01.1.dar").write_bytes(b"x" * 512 * 1024)

    util.list_backups(str(backup_dir))

    out = capsys.readouterr().out
    assert "homedir_FULL_2025-01-01" in out
    assert "homedir_DIFF_2025-02-01" in out


def test_list_backups_does_not_corrupt_process_locale(tmp_path, capsys):
    """Regression: after list_backups() returns, open() must still handle non-ASCII
    content with the default encoding.

    Previously list_backups() called locale.setlocale(LC_ALL, 'C') without restoring
    it, which permanently changed the process locale to ASCII on systems where the
    preferred locale (e.g. en_US.UTF-8) is not installed — causing all subsequent
    open() calls without an explicit encoding to raise UnicodeEncodeError on æøå, ✓
    and similar characters."""
    import locale as _locale

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    (backup_dir / "homedir_FULL_2025-01-01.1.dar").write_bytes(b"x" * 1024)

    preferred_before = _locale.getpreferredencoding(False)
    util.list_backups(str(backup_dir))
    preferred_after = _locale.getpreferredencoding(False)

    assert preferred_after == preferred_before, (
        f"list_backups() changed locale.getpreferredencoding from "
        f"{preferred_before!r} to {preferred_after!r}"
    )

    # If the locale were corrupted to ASCII this would raise UnicodeEncodeError
    with open(str(tmp_path / "danish_æøå.txt"), 'w') as f:
        f.write("This is file with danish chars æøå and checkmark ✓")


# ---------------------------------------------------------------------------
# ArchiveName tests
# ---------------------------------------------------------------------------

from dar_backup.util import ArchiveName
from datetime import datetime as _datetime


def test_archive_name_parse_valid_no_time():
    """Standard archive name without optional time component."""
    an = ArchiveName.parse("media_FULL_2026-01-15")
    assert an is not None
    assert an.definition == "media"
    assert an.archive_type == "FULL"
    assert an.date == "2026-01-15"
    assert an.time is None


def test_archive_name_parse_valid_with_time():
    """Archive name that includes the optional HHMMSS time suffix."""
    an = ArchiveName.parse("media_DIFF_2026-01-15_143022")
    assert an is not None
    assert an.definition == "media"
    assert an.archive_type == "DIFF"
    assert an.date == "2026-01-15"
    assert an.time == "143022"


def test_archive_name_parse_definition_with_underscores():
    """Backup definitions that contain underscores must be captured in full."""
    an = ArchiveName.parse("my_home_backup_INCR_2026-03-01")
    assert an is not None
    assert an.definition == "my_home_backup"
    assert an.archive_type == "INCR"


def test_archive_name_parse_invalid_returns_none():
    """Names that do not follow the convention must return None, not raise."""
    assert ArchiveName.parse("invalidarchive") is None
    assert ArchiveName.parse("") is None
    assert ArchiveName.parse(None) is None  # type: ignore[arg-type]


def test_archive_name_as_datetime_no_time():
    """as_datetime() builds a date-only datetime when time is absent."""
    an = ArchiveName.parse("media_FULL_2026-06-10")
    assert an is not None
    assert an.as_datetime() == _datetime(2026, 6, 10)


def test_archive_name_as_datetime_with_time():
    """as_datetime() incorporates the HHMMSS time when present."""
    an = ArchiveName.parse("media_FULL_2026-06-10_083045")
    assert an is not None
    assert an.as_datetime() == _datetime(2026, 6, 10, 8, 30, 45)


def test_archive_name_from_filename_strips_extension():
    """from_filename() strips path and .N.dar suffix before parsing."""
    an = ArchiveName.from_filename("/backups/media_DIFF_2026-01-15.1.dar")
    assert an is not None
    assert an.definition == "media"
    assert an.archive_type == "DIFF"
    assert an.date == "2026-01-15"


def _make_prereq_settings(script: str, timeout_secs: int = 30) -> SimpleNamespace:
    """Build a minimal config_settings stub for requirements() with one PREREQ script."""
    config = configparser.ConfigParser()
    config["PREREQ"] = {"PREREQ_01": script}
    return SimpleNamespace(config=config, command_timeout_secs=timeout_secs)


def test_requirements_background_child_does_not_hang(logger):
    """PREREQ script that spawns a background child must not block requirements().

    Before the fix (no start_new_session / no process-group kill), the background
    child inherited the stdout/stderr pipe FDs from the shell.  After the shell
    exited, the child kept those FDs open, so stdout_thread.join() blocked until
    the child eventually finished — potentially minutes later.

    With the fix, the entire process group is killed after the shell exits, so
    the pipes are closed and requirements() returns quickly.
    """
    settings = _make_prereq_settings("sleep 100 &")

    result: list = []
    exc: list = []

    def run() -> None:
        try:
            util.requirements("PREREQ", settings)
            result.append("ok")
        except Exception as e:
            exc.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=10)

    assert not t.is_alive(), (
        "requirements() is still running after 10 s — background child held the pipe open"
    )
    assert not exc, f"requirements() raised unexpectedly: {exc[0]}"
    assert result == ["ok"]


def test_requirements_timeout_raises_without_hanging(logger):
    """A PREREQ that exceeds its timeout must raise RuntimeError promptly.

    Before the fix, process.kill() only killed the shell; the child process
    (sleep 100) kept the pipe open, so stdout_thread.join() blocked long after
    the timeout fired.  With the fix, the process group is killed and the join
    completes quickly.
    """
    # shell=True makes /bin/sh spawn sleep 100 as a child; both shell and child
    # must be killed for the reader threads to see EOF.
    settings = _make_prereq_settings("sleep 100", timeout_secs=2)

    raised: list = []

    def run() -> None:
        try:
            util.requirements("PREREQ", settings)
        except RuntimeError as e:
            raised.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    # Allow 10 s: the configured timeout is 2 s, so the thread should finish
    # well within that window if the fix is working.
    t.join(timeout=10)

    assert not t.is_alive(), (
        "requirements() is still running after 10 s — timeout handler hung on join()"
    )
    assert raised, "requirements() should have raised RuntimeError on timeout"
    assert "timed out" in str(raised[0]).lower(), f"Unexpected error message: {raised[0]}"


def test_validate_directory_valid_returns_none(tmp_path):
    from dar_backup.util import validate_directory

    assert validate_directory(str(tmp_path), "TEST_DIR") is None


def test_validate_directory_valid_no_write_check_returns_none(tmp_path):
    from dar_backup.util import validate_directory

    assert validate_directory(str(tmp_path), "TEST_DIR", require_write=False) is None


def test_validate_directory_empty_path_reports_not_set():
    from dar_backup.util import validate_directory

    error = validate_directory("", "MY_DIR")
    assert error == "MY_DIR is not set"


def test_validate_directory_none_path_reports_not_set():
    from dar_backup.util import validate_directory

    error = validate_directory(None, "MY_DIR")
    assert error == "MY_DIR is not set"


def test_validate_directory_missing_path_reports_does_not_exist(tmp_path):
    from dar_backup.util import validate_directory

    missing = str(tmp_path / "missing")
    error = validate_directory(missing, "MY_DIR")
    assert error == f"MY_DIR does not exist: {missing}"


def test_validate_directory_file_path_reports_not_a_directory(tmp_path):
    from dar_backup.util import validate_directory

    f = tmp_path / "file.txt"
    f.write_text("x")
    error = validate_directory(str(f), "MY_DIR")
    assert error == f"MY_DIR exists but is not a directory: {f}"


def test_validate_directory_not_writable_reports_not_writable(tmp_path):
    from dar_backup.util import validate_directory

    with patch("os.access", return_value=False):
        error = validate_directory(str(tmp_path), "MY_DIR")
    assert error == f"MY_DIR is not writable: {tmp_path}"


def test_validate_directory_not_writable_skipped_when_not_required(tmp_path):
    from dar_backup.util import validate_directory

    with patch("os.access", return_value=False):
        error = validate_directory(str(tmp_path), "MY_DIR", require_write=False)
    assert error is None


def test_archive_exists_returns_true_when_slice_present(tmp_path):
    from dar_backup.util import archive_exists

    base = str(tmp_path / "mydef_FULL_2026-01-01")
    (tmp_path / "mydef_FULL_2026-01-01.1.dar").touch()
    assert archive_exists(base) is True


def test_archive_exists_returns_false_when_slice_absent(tmp_path):
    from dar_backup.util import archive_exists

    base = str(tmp_path / "mydef_FULL_2026-01-01")
    assert archive_exists(base) is False


def test_get_backup_definition_root_parses_r_line(tmp_path):
    from dar_backup.util import get_backup_definition_root

    backup_def = tmp_path / "example"
    backup_def.write_text("-R /data\n-s 10G\n")
    assert get_backup_definition_root(str(backup_def)) == "/data"


def test_get_backup_definition_root_handles_quoted_spaces_and_non_ascii(tmp_path):
    """A -R value with a space must be quoted for dar's own -B reference-file
    parser to treat it as one argument (confirmed against real dar: an
    unquoted value with spaces is split into multiple invalid targets) — the
    surrounding quotes must be stripped to recover the real filesystem path.
    """
    from dar_backup.util import get_backup_definition_root

    root_with_space_and_utf8 = "/mnt/backup source/café ünïcödé 日本語"
    backup_def = tmp_path / "example"
    backup_def.write_text(f'-R "{root_with_space_and_utf8}"\n-s 10G\n', encoding="utf-8")
    assert get_backup_definition_root(str(backup_def)) == root_with_space_and_utf8


def test_get_backup_definition_root_handles_single_and_back_quotes(tmp_path):
    """dar also accepts simple ('arg') and back-quotes (`arg`), per its manual."""
    from dar_backup.util import get_backup_definition_root

    backup_def = tmp_path / "example"
    backup_def.write_text("-R 'backup dir'\n", encoding="utf-8")
    assert get_backup_definition_root(str(backup_def)) == "backup dir"

    backup_def.write_text("-R `backup dir`\n", encoding="utf-8")
    assert get_backup_definition_root(str(backup_def)) == "backup dir"


def test_get_backup_definition_root_returns_none_when_no_r_line(tmp_path):
    from dar_backup.util import get_backup_definition_root

    backup_def = tmp_path / "example"
    backup_def.write_text("-s 10G\n-z6\n")
    assert get_backup_definition_root(str(backup_def)) is None


def test_get_backup_definition_root_returns_none_when_file_missing(tmp_path):
    from dar_backup.util import get_backup_definition_root

    missing = tmp_path / "does_not_exist"
    assert get_backup_definition_root(str(missing)) is None


def test_resolve_ownership_flag_preserve_ownership_wins(tmp_path):
    from types import SimpleNamespace
    from dar_backup.util import resolve_ownership_flag

    args = SimpleNamespace(preserve_ownership=True, ignore_ownership=True)
    config = SimpleNamespace(restore_ownership=True)
    assert resolve_ownership_flag(args, config) is False


def test_resolve_ownership_flag_ignore_ownership_wins_over_config(tmp_path):
    from types import SimpleNamespace
    from dar_backup.util import resolve_ownership_flag

    args = SimpleNamespace(preserve_ownership=False, ignore_ownership=True)
    config = SimpleNamespace(restore_ownership=True)
    assert resolve_ownership_flag(args, config) is True


def test_resolve_ownership_flag_falls_back_to_config_restore_ownership_true(tmp_path):
    from types import SimpleNamespace
    from dar_backup.util import resolve_ownership_flag

    args = SimpleNamespace(preserve_ownership=False, ignore_ownership=False)
    config = SimpleNamespace(restore_ownership=True)
    assert resolve_ownership_flag(args, config) is False


def test_resolve_ownership_flag_falls_back_to_config_restore_ownership_false(tmp_path):
    from types import SimpleNamespace
    from dar_backup.util import resolve_ownership_flag

    args = SimpleNamespace(preserve_ownership=False, ignore_ownership=False)
    config = SimpleNamespace(restore_ownership=False)
    assert resolve_ownership_flag(args, config) is True


def test_resolve_ownership_flag_missing_attrs_default_to_config(tmp_path):
    from types import SimpleNamespace
    from dar_backup.util import resolve_ownership_flag

    args = SimpleNamespace()  # no preserve_ownership or ignore_ownership
    config = SimpleNamespace(restore_ownership=True)
    assert resolve_ownership_flag(args, config) is False
