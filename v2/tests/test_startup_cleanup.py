import os
from unittest.mock import patch, MagicMock
from types import SimpleNamespace
from dar_backup.dar_backup import clean_restore_test_directory
import dar_backup.dar_backup as db
import pytest

pytestmark = pytest.mark.unit




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

def test_main_cleans_restore_dir_for_default_restore(monkeypatch, tmp_path):
    """
    Integration test ensuring main() cleans the restore test directory for default restores.
    """
    from dar_backup import dar_backup

    config_file = tmp_path / "dar-backup.conf"
    config_file.touch()
    monkeypatch.setattr(
        "sys.argv",
        ["dar-backup", "--config-file", str(config_file), "--restore", "example_FULL_2024-01-01"],
    )

    monkeypatch.setattr(dar_backup, "get_config_file", lambda args: str(config_file))

    mock_settings = MagicMock()
    mock_settings.logfile_location = str(tmp_path / "dar-backup.log")
    mock_settings.logfile_max_bytes = 1000
    mock_settings.logfile_backup_count = 1
    mock_settings.backup_d_dir = str(tmp_path / "backup.d")
    mock_settings.backup_dir = str(tmp_path / "backups")
    mock_settings.test_restore_dir = str(tmp_path / "restore")
    monkeypatch.setattr(dar_backup, "ConfigSettings", lambda cf: mock_settings)

    monkeypatch.setattr(dar_backup, "validate_required_directories", lambda s: None)
    monkeypatch.setattr(dar_backup, "preflight_check", lambda a, s: True)
    monkeypatch.setattr(dar_backup, "setup_logging", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "get_logger", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "CommandRunner", MagicMock())
    monkeypatch.setattr(dar_backup, "requirements", lambda *args, **kwargs: None)
    monkeypatch.setattr(dar_backup, "restore_backup", lambda *args, **kwargs: [])

    mock_clean = MagicMock()
    monkeypatch.setattr(dar_backup, "clean_restore_test_directory", mock_clean)

    try:
        dar_backup.main()
    except SystemExit:
        pass
    except Exception:
        pass

    mock_clean.assert_called_once_with(mock_settings)


def test_main_skips_clean_for_list_contents(monkeypatch, tmp_path):
    """
    Integration test ensuring main() does not clean restore dir for list-contents.
    """
    from dar_backup import dar_backup

    config_file = tmp_path / "dar-backup.conf"
    config_file.touch()
    monkeypatch.setattr(
        "sys.argv",
        ["dar-backup", "--config-file", str(config_file), "--list-contents", "example_FULL_2024-01-01"],
    )

    monkeypatch.setattr(dar_backup, "get_config_file", lambda args: str(config_file))

    mock_settings = MagicMock()
    mock_settings.logfile_location = str(tmp_path / "dar-backup.log")
    mock_settings.logfile_max_bytes = 1000
    mock_settings.logfile_backup_count = 1
    mock_settings.backup_d_dir = str(tmp_path / "backup.d")
    mock_settings.backup_dir = str(tmp_path / "backups")
    mock_settings.test_restore_dir = str(tmp_path / "restore")
    monkeypatch.setattr(dar_backup, "ConfigSettings", lambda cf: mock_settings)

    monkeypatch.setattr(dar_backup, "validate_required_directories", lambda s: None)
    monkeypatch.setattr(dar_backup, "preflight_check", lambda a, s: True)
    monkeypatch.setattr(dar_backup, "setup_logging", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "get_logger", lambda *args, **kwargs: MagicMock())
    monkeypatch.setattr(dar_backup, "CommandRunner", MagicMock())
    monkeypatch.setattr(dar_backup, "requirements", lambda *args, **kwargs: None)
    monkeypatch.setattr(dar_backup, "list_contents", lambda *args, **kwargs: None)

    mock_clean = MagicMock()
    monkeypatch.setattr(dar_backup, "clean_restore_test_directory", mock_clean)

    try:
        dar_backup.main()
    except SystemExit:
        pass
    except Exception:
        pass

    mock_clean.assert_not_called()
