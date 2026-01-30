import os
import pytest
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from dar_backup.dar_backup import clean_restore_test_directory
import dar_backup.dar_backup as db

def test_clean_restore_test_directory_removes_files(tmp_path):
    # Setup
    restore_dir = tmp_path / "restore_test"
    restore_dir.mkdir()
    
    (restore_dir / "file1.txt").write_text("content")
    (restore_dir / "subdir").mkdir()
    (restore_dir / "subdir" / "file2.txt").write_text("content2")
    
    config = SimpleNamespace(test_restore_dir=str(restore_dir))
    
    # Mock the global logger in dar_backup module
    mock_logger = MagicMock()
    with patch.object(db, "logger", mock_logger):
        clean_restore_test_directory(config)
        
        # Verify
        assert not (restore_dir / "file1.txt").exists()
        assert not (restore_dir / "subdir").exists()
        assert restore_dir.exists() # Directory itself should remain
        
        mock_logger.debug.assert_any_call(f"Cleaning restore test directory: {str(restore_dir)}")

def test_clean_restore_test_directory_skips_critical_paths():
    # Test skipping a critical path
    critical = "/etc" # Using a real path that is in the critical list
    config = SimpleNamespace(test_restore_dir=critical)
    
    mock_logger = MagicMock()
    with patch.object(db, "logger", mock_logger):
        clean_restore_test_directory(config)
        mock_logger.warning.assert_called_with(f"Refusing to clean critical directory: {critical}")

def test_clean_restore_test_directory_skips_home(monkeypatch):
    # Test skipping home directory
    home = os.path.expanduser("~")
    config = SimpleNamespace(test_restore_dir=home)
    
    mock_logger = MagicMock()
    with patch.object(db, "logger", mock_logger):
        clean_restore_test_directory(config)
        mock_logger.warning.assert_called_with(f"Refusing to clean user home directory: {home}")

def test_clean_restore_test_directory_skips_symlinked_critical_path(tmp_path):
    # Create a symlink pointing to a critical directory (e.g., /etc)
    # We use a safe critical path that exists, e.g., /tmp or just mock it?
    # realpath will resolve /tmp -> /tmp.
    # Let's create a dummy critical dir structure in tmp_path to be safe and predictable
    
    fake_root = tmp_path / "fake_root"
    fake_root.mkdir()
    fake_etc = fake_root / "etc"
    fake_etc.mkdir()
    
    # We can't easily mock os.path.realpath to point to real /etc without privileges or side effects,
    # but we can verify the logic by making our fake_etc be the "critical path" in our test context,
    # OR we can just rely on the fact that we changed the code to use realpath.
    
    # Better: Mock os.path.realpath to return a critical path when called with our symlink
    
    restore_dir_link = tmp_path / "link_to_critical"
    # We don't even need to create the link on disk if we mock realpath, 
    # but let's try to be as real as possible.
    # Pointing to /tmp is safe enough to test if we add /tmp to critical list check (it is there).
    
    # However, cleaning /tmp is valid if it's the restore dir?
    # The code lists /tmp as critical: ["/", ..., "/tmp", ...]
    # So if we symlink to /tmp, it should refuse.
    
    restore_dir_link.symlink_to("/tmp")
    
    config = SimpleNamespace(test_restore_dir=str(restore_dir_link))
    
    mock_logger = MagicMock()
    
    # We need to make sure the code sees /tmp as critical. It is in the list.
    
    with patch.object(db, "logger", mock_logger):
        clean_restore_test_directory(config)
        
        # It should resolve the link to /tmp (or /private/tmp on mac, but this is linux)
        # and refuse.
        # Note: os.path.realpath("/tmp") might be just "/tmp".
        
        # To be robust against environment differences, check that warning was called.
        if mock_logger.warning.called:
            args, _ = mock_logger.warning.call_args
            assert "Refusing to clean critical directory" in args[0]
        else:
            pytest.fail("Should have refused to clean symlinked critical directory")

def test_clean_restore_test_directory_allows_subdirectory_of_critical(tmp_path):
    # Test that a subdirectory of a critical path IS allowed.
    # tmp_path is usually under /tmp, which is critical.
    # So tmp_path itself should be allowed because it is /tmp/pytest-of-user/... 
    # not exactly /tmp.
    
    restore_dir = tmp_path / "allowed_subdir"
    restore_dir.mkdir()
    (restore_dir / "can_delete_me.txt").touch()
    
    config = SimpleNamespace(test_restore_dir=str(restore_dir))
    
    mock_logger = MagicMock()
    
    with patch.object(db, "logger", mock_logger):
        clean_restore_test_directory(config)
        
        # Should NOT have warned about critical directory
        # (It might warn about other things if deletion failed, but we expect success here)
        
        # Check if file was deleted
        assert not (restore_dir / "can_delete_me.txt").exists()
        
        # Ensure no "Refusing to clean" warnings
        for call in mock_logger.warning.call_args_list:
            args, _ = call
            assert "Refusing to clean" not in str(args[0])

def test_clean_restore_test_directory_handles_errors(tmp_path):
    # Test error handling during deletion
    restore_dir = tmp_path / "restore_test_err"
    restore_dir.mkdir()
    file_path = restore_dir / "protected.txt"
    file_path.touch()
    
    config = SimpleNamespace(test_restore_dir=str(restore_dir))
    
    mock_logger = MagicMock()
    
    # Mock os.unlink to raise exception
    with patch.object(db, "logger", mock_logger), \
         patch("os.unlink", side_effect=PermissionError("Access denied")):
        
        clean_restore_test_directory(config)
        
        mock_logger.warning.assert_called()
        # Verify the warning contains the error message
        args, _ = mock_logger.warning.call_args
        assert "Access denied" in str(args[0])

def test_main_calls_clean_restore_test_directory(monkeypatch, tmp_path):
    """
    Integration test ensuring main() actually calls clean_restore_test_directory.
    """
    from dar_backup import dar_backup
    
    # Mock sys.argv
    config_file = tmp_path / "dar-backup.conf"
    config_file.touch()
    monkeypatch.setattr("sys.argv", ["dar-backup", "--config-file", str(config_file)])
    
    # Mock dependencies to reach the call site in main()
    monkeypatch.setattr(dar_backup, "get_config_file", lambda args: str(config_file))
    
    # Mock ConfigSettings
    mock_settings = MagicMock()
    mock_settings.logfile_location = str(tmp_path / "dar-backup.log")
    # Need these attributes for main() to proceed
    mock_settings.logfile_max_bytes = 1000
    mock_settings.logfile_backup_count = 1
    mock_settings.backup_d_dir = str(tmp_path / "backup.d")
    monkeypatch.setattr(dar_backup, "ConfigSettings", lambda cf: mock_settings)
    
    # Mock other checks
    monkeypatch.setattr(dar_backup, "validate_required_directories", lambda s: None)
    monkeypatch.setattr(dar_backup, "preflight_check", lambda a, s: True)
    
    # Mock logging and runner
    monkeypatch.setattr(dar_backup, "setup_logging", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "get_logger", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "CommandRunner", MagicMock())
    
    # IMPORTANT: Mock clean_restore_test_directory to verify it's called
    mock_clean = MagicMock()
    monkeypatch.setattr(dar_backup, "clean_restore_test_directory", mock_clean)
    
    # We want to stop main() after the call we're testing, but before it tries to run backups
    # We can do this by raising a SystemExit in the subsequent code or just mocking the rest.
    # The call happens before argument processing for backups.
    # Let's just let it run until it hits something we haven't mocked or finishes.
    # Since we didn't provide any backup arguments, main() will likely just print settings and exit or do nothing.
    # But main() accesses args.darrc which might fail if we don't handle it.
    
    # Mocking arguments parsing result if needed, but sys.argv mocking handles argparse mostly.
    # However, main calls:
    #   if not args.darrc: ...
    # which implies successful parsing.
    
    # To cleanly exit main without running actual backup logic (which requires more mocks),
    # we can mock 'requirements' or similar, OR just let it finish. 
    # If no backup args (full/diff/incr) are present, main falls through to "stats" print and exit?
    # Actually looking at main code, it seems to fall through if no action arguments are set.
    
    # Let's try running main and catching SystemExit (if any)
    try:
        dar_backup.main()
    except SystemExit:
        pass
    except Exception:
        # If it crashes due to unmocked stuff later, that's fine as long as our target was called.
        pass
        
    mock_clean.assert_called_once_with(mock_settings)
