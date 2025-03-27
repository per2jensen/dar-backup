
import os
import subprocess
from dar_backup.util import run_command


def test_backup_with_broken_symlink(setup_environment, env):
    """Ensure that dar-backup handles broken symlinks gracefully during full backup."""

    # Setup a broken symlink in the data dir
    broken_link = os.path.join(env.data_dir, "broken_link")
    os.symlink("/non/existent/target", broken_link)
    assert os.path.islink(broken_link)
    assert not os.path.exists(broken_link)  # Confirm it's broken

    # Also add a real file (just to trigger archive creation)
    with open(os.path.join(env.data_dir, "real.txt"), "w") as f:
        f.write("real content\n")

    # Run full backup
    result = run_command(["dar-backup", "--full-backup", "--config-file", env.config_file])
    env.logger.info("Ran dar-backup with a broken symlink in the data directory")

    # The backup should either succeed or report non-critical issues (return code 0 or 5)
    assert result.returncode in (0, 5), f"Unexpected return code: {result.returncode}"

    # Derive expected archive path
    expected_archive_base = os.path.join(env.backup_dir, "example")
    expected_archive = f"{expected_archive_base}_FULL_{env.datestamp}.1.dar"
    assert os.path.exists(expected_archive), f"Expected archive not found: {expected_archive}"


    # Use the dar-backup list-contents to inspect archive contents
    list_result = run_command([
        "dar-backup",
        "--list-contents", f"{expected_archive_base}_FULL_{env.datestamp}",
        "--config-file", env.config_file
    ])
    env.logger.info("Listed contents of archive with broken symlink")

    # Output should mention the symlink (dar shows them with 'l' in type column)
    assert "broken_link" in list_result.stdout or "broken_link" in list_result.stderr

