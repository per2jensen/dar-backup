import os
import re
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from datetime import datetime
from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner


def _find_slice_par2_files(backup_dir: str, archive_base: str) -> list:
    """Return sorted list of per-slice .par2 index paths for archive_base.

    With per-slice par2 generation each slice produces its own par2 set named
    {slice_file}.par2  (e.g. example_FULL_2026-06-06.1.dar.par2).
    """
    import re as _re
    pattern = _re.compile(rf"{_re.escape(archive_base)}\.([0-9]+)\.dar\.par2$")
    slices = sorted(
        [f for f in os.listdir(backup_dir) if pattern.match(f)],
        key=lambda x: int(pattern.match(x).group(1))
    )
    return [os.path.join(backup_dir, f) for f in slices]







"""
This module tests the par2 file creation and repair functionality of dar-backup.
Also see the test_bitrot.py module for more tests on the par2 functionality.
"""


def create_random_data_file(env: EnvData, name, size):
    """
    Create a file with random data of a specific size.

    Args:
        name (str): The name of the file.
        size (int): The size of the file in bytes.
    """
    filename = f"random-{name}"
    with open(os.path.join(env.test_dir, "data", filename), 'wb') as f:
        f.write(os.urandom(size))
        env.logger.info(f'Created {os.path.join(env.test_dir, "data", filename)} of size {name}')



def generate_datafiles(env: EnvData, file_sizes: dict) -> None:
    """
    Generate the data files for testing.

    This method creates files of different sizes using the create_random_data_file method.
    """
    try:
        # Create files
        for name, size in file_sizes.items():
            create_random_data_file(env, name, size)
    except Exception:
        env.logger.exception("data file generation failed")
        raise


def modify_slice_size(env: EnvData, definition: str, slice_size: str) -> None:
    """
    Modify the redundancy level of the par2 files by patching the dar-backup.conf file

    Args:
        env (EnvData): The environment data object.
        definition (str): The backup definition file to modify. Fx `example`
        slice_size (str): fx `1k`
    Raises:
        RuntimeError: If the command fails.
    """
    print("Definition", definition)
    print("test_dir", env.test_dir) 
    definition_path = os.path.join(env.test_dir, 'backup.d', definition)
    print("Definition path ", definition_path)

    with open(definition_path, 'r') as f:
        lines = f.readlines()
    with open(definition_path, 'w') as f:
        for line in lines:
            if line.startswith('-s '):
                f.write(f'-s {slice_size}\n')
            else:
                f.write(line)


def test_ordered_by_slicenumber(setup_environment, env):
    date = datetime.now().strftime('%Y-%m-%d')
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)


    dummy_dar_files = {f'{date}-1' : 1024,
                        f'{date}-2': 2048,
                        f'{date}-3': 4096,}
    generate_datafiles(env, dummy_dar_files)
    
    modify_slice_size(env, 'example', '1k')    

    command = ['dar-backup', '-F', '-d', "example", '--verbose', '--log-stdout', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"Error running backup command: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Error running backup command: {command}")

    # With per-slice par2 generation there is one par2 create command per slice.
    # Extract the slice number from each command and verify they are emitted in
    # ascending order.
    par2_command_lines = [
        line for line in stdout.splitlines()
        if "Executing command:" in line and "par2 create" in line
    ]
    assert par2_command_lines, f"No par2 create commands found in stdout: {stdout}"
    slice_pattern = re.compile(r'\.(\d+)\.dar')
    slice_numbers = []
    for cmd_line in par2_command_lines:
        m = slice_pattern.search(cmd_line)
        if m:
            slice_numbers.append(int(m.group(1)))
    assert slice_numbers, f"No slice numbers found in par2 commands: {par2_command_lines}"
    assert len(slice_numbers) > 0, "There must be at least 1 dar slice, got 0"

    # Verify that commands are issued in ascending slice-number order
    assert slice_numbers == sorted(slice_numbers), f"Slices not processed in order: {slice_numbers}"

    env.logger.info(f"OK: slices processed in order: {slice_numbers}")


def test_par2_files_created_for_full_backup(setup_environment, env):
    """A full backup with PAR2 enabled must produce .par2 files in the backup directory."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['dar-backup', '--full-backup', '-d', 'example', '--config-file', env.config_file]
    process = runner.run(command)
    assert process.returncode == 0, f"Backup failed: {process.stderr}"

    archive_base = f"example_FULL_{env.datestamp}"
    par2_files = [f for f in os.listdir(env.backup_dir) if f.startswith(archive_base) and f.endswith('.par2')]
    assert par2_files, f"No .par2 files found in {env.backup_dir} after FULL backup"


def test_par2_verify_passes_on_intact_backup(setup_environment, env):
    """par2 verify must succeed on an intact backup (no corruption)."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['dar-backup', '--full-backup', '-d', 'example', '--config-file', env.config_file]
    process = runner.run(command)
    assert process.returncode == 0, f"Backup failed: {process.stderr}"

    archive_base = f"example_FULL_{env.datestamp}"
    # Per-slice par2: verify every slice's par2 set individually.
    slice_par2_files = _find_slice_par2_files(env.backup_dir, archive_base)
    assert slice_par2_files, f"No per-slice par2 index files found for {archive_base}"
    for par2_index in slice_par2_files:
        verify = runner.run(['par2', 'verify', '-B', env.backup_dir, par2_index])
        assert verify.returncode == 0, (
            f"par2 verify failed on intact backup ({os.path.basename(par2_index)}): "
            f"{verify.stderr}"
        )

