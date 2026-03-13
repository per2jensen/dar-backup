"""
Tests for _resolve_safe_path() and _BlockedPathError in generate_clone_dashboard.

Covers:
- Valid file is accepted and returned as its canonical absolute path
- Relative path with '..' traversal is resolved before checking (traversal caught)
- Non-existent path raises ValueError
- Directory path raises ValueError (not a regular file)
- Named pipe / device files are rejected as not-a-regular-file
- Each blocked system directory is rejected
- Symlink pointing into a blocked directory is rejected
- Symlink pointing to a valid temp file is accepted
- _BlockedPathError is a subclass of ValueError
"""

import os
import pathlib
import tempfile

import pytest

from clonepulse.generate_clone_dashboard import (
    _BLOCKED_PATH_PREFIXES,
    _BlockedPathError,
    _resolve_safe_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_temp_json() -> str:
    """Create a real temporary file and return its path (caller must delete)."""
    fd, path = tempfile.mkstemp(suffix=".json")
    os.write(fd, b'{"daily": []}')
    os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Positive tests
# ---------------------------------------------------------------------------

class TestResolveSafePathPositive:
    def test_valid_file_is_accepted(self):
        """A regular file in /tmp must be accepted and returned as absolute path."""
        path = _make_temp_json()
        try:
            result = _resolve_safe_path(path, "--downloads-file")
            assert os.path.isabs(result)
            assert os.path.isfile(result)
        finally:
            os.unlink(path)

    def test_returns_canonical_path(self):
        """The returned path must be the resolved canonical form."""
        path = _make_temp_json()
        try:
            result = _resolve_safe_path(path, "--downloads-file")
            assert result == str(pathlib.Path(path).resolve())
        finally:
            os.unlink(path)

    def test_symlink_to_valid_file_is_accepted(self, tmp_path):
        """A symlink whose target is a regular file in a safe directory is accepted."""
        target = tmp_path / "data.json"
        target.write_text('{"daily": []}')
        link = tmp_path / "link.json"
        link.symlink_to(target)
        result = _resolve_safe_path(str(link), "--downloads-file")
        # Resolved path must equal the real target, not the link
        assert result == str(target.resolve())

    def test_blocked_path_error_is_value_error_subclass(self):
        """_BlockedPathError must be a subclass of ValueError."""
        assert issubclass(_BlockedPathError, ValueError)

    def test_label_appears_in_error_message(self):
        """The label argument must appear in any raised error message."""
        with pytest.raises(ValueError, match="my-custom-label"):
            _resolve_safe_path("/etc/passwd", "my-custom-label")


# ---------------------------------------------------------------------------
# Negative tests — not a regular file
# ---------------------------------------------------------------------------

class TestResolveSafePathNotAFile:
    def test_nonexistent_path_raises(self):
        """A path that does not exist must raise ValueError."""
        with pytest.raises(ValueError, match="does not resolve to a regular file"):
            _resolve_safe_path("/tmp/this_file_does_not_exist_xyz.json", "--downloads-file")

    def test_directory_path_raises(self, tmp_path):
        """A path that resolves to a directory must raise ValueError."""
        with pytest.raises(ValueError, match="does not resolve to a regular file"):
            _resolve_safe_path(str(tmp_path), "--downloads-file")

    def test_named_pipe_raises(self, tmp_path):
        """A named pipe must be rejected (not a regular file)."""
        pipe = tmp_path / "fifo"
        os.mkfifo(str(pipe))
        with pytest.raises(ValueError, match="does not resolve to a regular file"):
            _resolve_safe_path(str(pipe), "--downloads-file")

    def test_device_file_raises(self):
        """/dev/null is a character device, not a regular file — must be rejected."""
        if not os.path.exists("/dev/null"):
            pytest.skip("/dev/null not available")
        with pytest.raises(ValueError, match="does not resolve to a regular file"):
            _resolve_safe_path("/dev/null", "--downloads-file")


# ---------------------------------------------------------------------------
# Negative tests — blocked system directories
# ---------------------------------------------------------------------------

class TestResolveSafePathBlockedDirs:
    @pytest.mark.parametrize("blocked_path", [
        "/etc/passwd",
        "/etc/hostname",
        "/root/.bashrc",
        "/proc/version",
        "/sys/kernel/hostname",
        "/boot/grub/grub.cfg",
        "/run/utmp",
        "/usr/bin/env",
        "/bin/sh",
        "/sbin/init",
    ])
    def test_blocked_system_paths_raise(self, blocked_path):
        """Paths inside blocked system directories must raise _BlockedPathError."""
        if not os.path.exists(blocked_path):
            pytest.skip(f"{blocked_path} does not exist on this system")
        with pytest.raises(_BlockedPathError):
            _resolve_safe_path(blocked_path, "--downloads-file")

    def test_all_blocked_prefixes_are_covered(self):
        """Every entry in _BLOCKED_PATH_PREFIXES must be an absolute Path."""
        for p in _BLOCKED_PATH_PREFIXES:
            assert p.is_absolute(), f"Blocked prefix is not absolute: {p}"

    def test_symlink_into_etc_is_blocked(self, tmp_path):
        """A symlink in /tmp whose target is inside /etc must be blocked."""
        if not os.path.exists("/etc/passwd"):
            pytest.skip("/etc/passwd not available")
        link = tmp_path / "evil_link.json"
        link.symlink_to("/etc/passwd")
        with pytest.raises(_BlockedPathError, match="blocked system directory"):
            _resolve_safe_path(str(link), "--downloads-file")

    def test_dotdot_traversal_into_etc_is_blocked(self):
        """A path with '..' components that resolves into /etc must be blocked."""
        if not os.path.exists("/etc/passwd"):
            pytest.skip("/etc/passwd not available")
        # Build an absolute path containing '..' that resolves to /etc/passwd:
        # /tmp/../etc/passwd  →  /etc/passwd
        traversal = "/tmp/../etc/passwd"
        with pytest.raises(_BlockedPathError, match="blocked system directory"):
            _resolve_safe_path(traversal, "--downloads-file")
