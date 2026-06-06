"""
Integration tests for PAR2 per-backup-definition configuration.

Covers the following permutations of the PAR2 configuration system:
  - Global ENABLED=False  → no par2 files created for any definition
  - Per-definition PAR2_ENABLED=False  → selective disable while global is on
  - Per-definition PAR2_DIR  → par2 files land in the configured directory
  - Per-definition PAR2_RATIO_FULL/DIFF/INCR  → different ratios per type
  - PAR2_RUN_VERIFY=True  → inline verification runs immediately after creation
  - Manifest file written when PAR2_DIR is set
  - Multi-definition isolation  → corrupting one archive does not affect another's par2 set
  - Ratio size ordering  → larger ratio produces a proportionally larger par2 set
"""

import configparser
import glob
import os
import sys

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from datetime import datetime

from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_random_file(path: str, size: int) -> None:
    """
    Write a file of random bytes at the given path.

    Args:
        path: Destination file path.
        size: Number of random bytes to write.
    """
    with open(path, "wb") as fh:
        fh.write(os.urandom(size))


def _dar_safe_path(path: str) -> str:
    """
    Strip the leading slash from an absolute path for use in dar -g arguments.

    Args:
        path: Absolute filesystem path.

    Returns:
        Path without the leading '/'.
    """
    return path.lstrip("/")


def _write_backup_definition(def_path: str, data_dir: str) -> None:
    """
    Write a minimal dar backup definition file targeting data_dir.

    Args:
        def_path: Destination path for the definition file.
        data_dir: Absolute path to the directory to be backed up.
    """
    content = "\n".join([
        "-R /",
        "-s 10M",
        "-z6",
        "-am",
        "--cache-directory-tagging",
        f"-g {_dar_safe_path(data_dir)}",
    ])
    with open(def_path, "w") as fh:
        fh.write(content + "\n")


def _configure_par2_overrides(env: EnvData, overrides: dict[str, dict[str, str]]) -> None:
    """
    Merge overrides into the test config file using ConfigParser.

    Each key in `overrides` is a section name; its value is a dict of
    option-name → value pairs.  Existing sections and options are preserved.

    Args:
        env: EnvData fixture providing the config file path.
        overrides: Mapping of section → {option: value} to apply.
    """
    config = configparser.ConfigParser()
    config.read(env.config_file)
    for section, values in overrides.items():
        if section not in config:
            config[section] = {}
        for key, value in values.items():
            config[section][key] = str(value)
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _find_archive_base(backup_dir: str, definition: str, date: str) -> str:
    """
    Return the archive base name (without .1.dar) for the first matching slice.

    Args:
        backup_dir: Directory containing .dar slices.
        definition: Backup definition name used as archive name prefix.
        date: Date string in YYYY-MM-DD format.

    Returns:
        Archive base name such as "media-files_FULL_2026-05-23".

    Raises:
        RuntimeError: If no matching slice is found.
    """
    pattern = os.path.join(backup_dir, f"{definition}_FULL_{date}.1.dar")
    matches = glob.glob(pattern)
    if not matches:
        raise RuntimeError(f"No archive slice found for pattern: {pattern}")
    return os.path.basename(matches[0]).rsplit(".1.dar", 1)[0]


def _flip_first_byte(path: str) -> None:
    """
    XOR the first byte of the file with 0xFF to introduce one-byte corruption.

    Args:
        path: Path to the file to corrupt.

    Raises:
        RuntimeError: If the file is empty.
    """
    with open(path, "r+b") as fh:
        original = fh.read(1)
        if not original:
            raise RuntimeError(f"Cannot corrupt empty file: {path}")
        fh.seek(0)
        fh.write(bytes([original[0] ^ 0xFF]))


def _run_backup(
    runner: CommandRunner,
    env: EnvData,
    definition: str,
    flag: str = "-F",
) -> str:
    """
    Run dar-backup for the given definition and return captured stdout.

    Args:
        runner: CommandRunner to use for the subprocess call.
        env: EnvData fixture providing the config file path.
        definition: Backup definition name to pass with -d.
        flag: Backup type flag: "-F" (full), "-D" (diff), "-I" (incr).

    Returns:
        Combined stdout from the dar-backup run.

    Raises:
        RuntimeError: If dar-backup exits with a non-zero return code.
    """
    result = runner.run([
        "dar-backup", flag, "-d", definition,
        "--config-file", env.config_file,
        "--log-level", "debug", "--log-stdout",
    ])
    if result.returncode != 0:
        raise RuntimeError(
            f"dar-backup {flag} failed for '{definition}' "
            f"(rc={result.returncode}):\n{result.stderr}"
        )
    return result.stdout


def _create_catalog_db(runner: CommandRunner, env: EnvData) -> None:
    """
    Run manager --create-db to initialise catalog databases for all definitions.

    Args:
        runner: CommandRunner to use for the subprocess call.
        env: EnvData fixture providing the config file path.

    Raises:
        RuntimeError: If manager --create-db exits with a non-zero return code.
    """
    result = runner.run([
        "manager", "--create-db",
        "--config-file", env.config_file,
        "--log-level", "debug", "--log-stdout",
    ])
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {result.stderr}")


def _par2_files_in(directory: str, archive_base: str) -> list[str]:
    """
    Return all par2 files for the given archive base in directory.

    Args:
        directory: Directory to search.
        archive_base: Archive base name without any extension.

    Returns:
        Sorted list of absolute paths to matching .par2 files.
    """
    return sorted(glob.glob(os.path.join(directory, f"{archive_base}*.par2")))


def _total_par2_size(directory: str, archive_base: str) -> int:
    """
    Return the total size in bytes of all par2 files for archive_base.

    Args:
        directory: Directory to search.
        archive_base: Archive base name without any extension.

    Returns:
        Sum of file sizes in bytes; 0 if no par2 files are found.
    """
    return sum(os.path.getsize(f) for f in _par2_files_in(directory, archive_base))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_par2_multi_definition_repair_flow(setup_environment, env: EnvData) -> None:
    """
    Three backup definitions each with distinct PAR2_DIR and PAR2_RATIO_FULL.

    For each definition:
      1. Run a real FULL backup.
      2. Assert par2 files landed in that definition's configured PAR2_DIR.
      3. Corrupt the archive slice.
      4. Confirm dar -t detects the corruption.
      5. Confirm par2 verify detects the corruption.
      6. Repair with par2 and confirm dar -t passes.
    """
    date = datetime.now().strftime("%Y-%m-%d")
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )

    definitions = {
        "media-files": {
            "data_dir": os.path.join(env.test_dir, "data_media"),
            "par2_dir": os.path.join(env.test_dir, "par2_media"),
            "ratio_full": 11,
        },
        "docs": {
            "data_dir": os.path.join(env.test_dir, "data_docs"),
            "par2_dir": os.path.join(env.test_dir, "par2_docs"),
            "ratio_full": 7,
        },
        "pics": {
            "data_dir": os.path.join(env.test_dir, "data_pics"),
            "par2_dir": os.path.join(env.test_dir, "par2_pics"),
            "ratio_full": 5,
        },
    }

    overrides: dict[str, dict[str, str]] = {}
    for name, cfg in definitions.items():
        os.makedirs(cfg["data_dir"], exist_ok=True)
        os.makedirs(cfg["par2_dir"], exist_ok=True)
        _write_random_file(os.path.join(cfg["data_dir"], "a.bin"), 512 * 1024)
        _write_random_file(os.path.join(cfg["data_dir"], "b.bin"), 512 * 1024)
        _write_backup_definition(
            os.path.join(env.backup_d_dir, name), cfg["data_dir"]
        )
        overrides[name] = {
            "PAR2_DIR": cfg["par2_dir"],
            "PAR2_RATIO_FULL": str(cfg["ratio_full"]),
        }

    _configure_par2_overrides(env, overrides)
    _create_catalog_db(runner, env)

    for name in definitions:
        _run_backup(runner, env, name)

    for name, cfg in definitions.items():
        archive_base = _find_archive_base(env.backup_dir, name, date)
        slice_path = os.path.join(env.backup_dir, f"{archive_base}.1.dar")
        # Per-slice par2: index files are named {slice_file}.par2.
        import re as _re
        sp = _re.compile(rf"{_re.escape(archive_base)}\.([0-9]+)\.dar\.par2$")
        slice_par2_files = sorted(
            [f for f in os.listdir(cfg["par2_dir"]) if sp.match(f)],
            key=lambda x: int(sp.match(x).group(1))
        )
        assert slice_par2_files, (
            f"No per-slice par2 files found in {cfg['par2_dir']} for '{name}'"
        )
        # None of them must appear in another definition's directory
        other_dirs = [c["par2_dir"] for n, c in definitions.items() if n != name]
        for other_dir in other_dirs:
            cross = [f for f in os.listdir(other_dir) if f.startswith(archive_base)]
            assert not cross, (
                f"par2 files for '{name}' must not appear in '{other_dir}': {cross}"
            )

        _flip_first_byte(slice_path)

        dar_corrupt = runner.run([
            "dar", "-t", os.path.join(env.backup_dir, archive_base), "-N", "-Q"
        ])
        assert dar_corrupt.returncode != 0, (
            f"dar -t must fail on the corrupted archive for '{name}'"
        )

        for slice_par2 in slice_par2_files:
            par2_path = os.path.join(cfg["par2_dir"], slice_par2)
            verify = runner.run(["par2", "verify", "-B", env.backup_dir, par2_path])
            assert verify.returncode != 0, (
                f"par2 verify must fail before repair for '{name}' ({slice_par2})"
            )
            repair = runner.run(["par2", "repair", "-B", env.backup_dir, par2_path])
            assert repair.returncode == 0, (
                f"par2 repair failed for '{name}' ({slice_par2}): {repair.stderr}"
            )

        dar_ok = runner.run([
            "dar", "-t", os.path.join(env.backup_dir, archive_base), "-N", "-Q"
        ])
        assert dar_ok.returncode == 0, (
            f"dar -t must pass after repair for '{name}': {dar_ok.stderr}"
        )


def test_par2_globally_disabled(setup_environment, env: EnvData) -> None:
    """
    When [PAR2] ENABLED = False no par2 files are created for any archive.

    Steps:
      1. Disable par2 globally via config override.
      2. Run a real FULL backup for the "example" definition.
      3. Assert the archive slice exists (backup succeeded).
      4. Assert no .par2 files are present in the backup directory.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )

    _configure_par2_overrides(env, {"PAR2": {"ENABLED": "False"}})

    _run_backup(runner, env, "example")

    date = datetime.now().strftime("%Y-%m-%d")
    slice_path = os.path.join(env.backup_dir, f"example_FULL_{date}.1.dar")
    assert os.path.exists(slice_path), (
        f"Archive slice must exist even when par2 is disabled: {slice_path}"
    )

    par2_files = glob.glob(os.path.join(env.backup_dir, "*.par2"))
    assert not par2_files, (
        f"No par2 files expected when ENABLED=False, found: {par2_files}"
    )


def test_par2_disabled_per_definition(setup_environment, env: EnvData) -> None:
    """
    Per-definition PAR2_ENABLED=False overrides global True for that definition.

    Two definitions are created:
      - "active":   inherits the global PAR2 settings → par2 files are created.
      - "inactive": has PAR2_ENABLED=False in its section → no par2 files created.

    Steps:
      1. Create definitions and catalog DBs.
      2. Configure [inactive] PAR2_ENABLED=False.
      3. Run FULL backups for both.
      4. Assert "active" has par2 files; "inactive" does not.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    for name in ("active", "inactive"):
        data_dir = os.path.join(env.test_dir, f"data_{name}")
        os.makedirs(data_dir, exist_ok=True)
        _write_random_file(os.path.join(data_dir, "payload.bin"), 256 * 1024)
        _write_backup_definition(os.path.join(env.backup_d_dir, name), data_dir)

    _configure_par2_overrides(env, {"inactive": {"PAR2_ENABLED": "False"}})
    _create_catalog_db(runner, env)

    for name in ("active", "inactive"):
        _run_backup(runner, env, name)

    active_base = _find_archive_base(env.backup_dir, "active", date)
    inactive_base = _find_archive_base(env.backup_dir, "inactive", date)

    active_par2 = _par2_files_in(env.backup_dir, active_base)
    assert active_par2, (
        f"Expected par2 files for 'active' in {env.backup_dir}, found none"
    )

    inactive_par2 = _par2_files_in(env.backup_dir, inactive_base)
    assert not inactive_par2, (
        f"Expected no par2 files for 'inactive' (PAR2_ENABLED=False), "
        f"found: {inactive_par2}"
    )


def test_par2_run_verify_triggers_on_creation(setup_environment, env: EnvData) -> None:
    """
    PAR2_RUN_VERIFY=True causes par2 verify to run immediately after par2 create.

    Steps:
      1. Configure PAR2_RUN_VERIFY=True globally.
      2. Run a FULL backup with --log-stdout.
      3. Assert backup succeeded → inline verify passed (otherwise dar-backup raises).
      4. Assert "Verifying par2 set" appears in the log output confirming the
         verify code path was reached.
      5. Assert par2 files exist on disk.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    _configure_par2_overrides(env, {"PAR2": {"PAR2_RUN_VERIFY": "True"}})

    stdout = _run_backup(runner, env, "example")

    assert "Verifying par2 for" in stdout, (
        f"Expected 'Verifying par2 for' in dar-backup output when "
        f"PAR2_RUN_VERIFY=True:\n{stdout}"
    )

    archive_base = _find_archive_base(env.backup_dir, "example", date)
    par2_files = _par2_files_in(env.backup_dir, archive_base)
    assert par2_files, (
        f"Expected par2 files on disk after a backup with PAR2_RUN_VERIFY=True"
    )


def test_par2_manifest_written_when_custom_dir(setup_environment, env: EnvData) -> None:
    """
    A .par2.manifest.ini file is written alongside the par2 index when a custom
    PAR2_DIR is configured.

    The manifest must contain:
      - [MANIFEST] section with archive_base and archive_dir_relative keys.
      - [ARCHIVE_FILES] section listing the dar slice filenames.

    Steps:
      1. Configure a per-definition PAR2_DIR.
      2. Run a FULL backup.
      3. Assert the manifest file exists in par2_dir.
      4. Parse the manifest and verify its content.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    par2_dir = os.path.join(env.test_dir, "par2_manifest_test")
    os.makedirs(par2_dir, exist_ok=True)

    data_dir = os.path.join(env.test_dir, "data_manifest")
    os.makedirs(data_dir, exist_ok=True)
    _write_random_file(os.path.join(data_dir, "content.bin"), 256 * 1024)
    _write_backup_definition(os.path.join(env.backup_d_dir, "mftest"), data_dir)
    _configure_par2_overrides(env, {"mftest": {"PAR2_DIR": par2_dir}})
    _create_catalog_db(runner, env)

    _run_backup(runner, env, "mftest")

    archive_base = _find_archive_base(env.backup_dir, "mftest", date)
    manifest_path = os.path.join(par2_dir, f"{archive_base}.par2.manifest.ini")

    assert os.path.exists(manifest_path), (
        f"Expected manifest file at: {manifest_path}"
    )

    manifest = configparser.ConfigParser()
    manifest.read(manifest_path)

    assert "MANIFEST" in manifest, (
        f"Expected [MANIFEST] section in {manifest_path}"
    )
    assert manifest["MANIFEST"].get("archive_base") == archive_base, (
        f"Expected archive_base='{archive_base}' in manifest, "
        f"got: {manifest['MANIFEST'].get('archive_base')}"
    )
    assert "archive_dir_relative" in manifest["MANIFEST"], (
        "Expected 'archive_dir_relative' key in [MANIFEST]"
    )

    assert "ARCHIVE_FILES" in manifest, (
        f"Expected [ARCHIVE_FILES] section in {manifest_path}"
    )
    files_entry = manifest["ARCHIVE_FILES"].get("files", "")
    assert archive_base in files_entry, (
        f"Expected archive_base '{archive_base}' referenced in [ARCHIVE_FILES]: {files_entry}"
    )


def test_par2_diff_and_incr_have_separate_par2_sets(setup_environment, env: EnvData) -> None:
    """
    FULL, DIFF, and INCR backups each produce a distinct par2 set when
    PAR2_RATIO_FULL, PAR2_RATIO_DIFF, and PAR2_RATIO_INCR are configured.

    Steps:
      1. Configure distinct ratios for FULL (15%), DIFF (10%), INCR (5%).
      2. Run FULL backup → assert FULL par2 files exist.
      3. Add new data files → run DIFF backup → assert DIFF par2 files exist.
      4. Add more data files → run INCR backup → assert INCR par2 files exist.
      5. Confirm the three par2 sets are distinct (no name overlap).
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    data_dir = os.path.join(env.test_dir, "data_chain")
    os.makedirs(data_dir, exist_ok=True)
    _write_random_file(os.path.join(data_dir, "base.bin"), 512 * 1024)
    _write_backup_definition(os.path.join(env.backup_d_dir, "chain"), data_dir)

    _configure_par2_overrides(env, {
        "chain": {
            "PAR2_RATIO_FULL": "15",
            "PAR2_RATIO_DIFF": "10",
            "PAR2_RATIO_INCR": "5",
        }
    })
    _create_catalog_db(runner, env)

    # FULL
    _run_backup(runner, env, "chain", flag="-F")
    full_slices = glob.glob(os.path.join(env.backup_dir, f"chain_FULL_{date}*.1.dar"))
    assert full_slices, "Expected FULL archive slice on disk"
    full_base = os.path.basename(full_slices[0]).rsplit(".1.dar", 1)[0]
    full_par2 = _par2_files_in(env.backup_dir, full_base)
    assert full_par2, f"Expected par2 files for FULL archive '{full_base}'"

    # DIFF — add new file so the archive is non-empty
    _write_random_file(os.path.join(data_dir, "diff_extra.bin"), 256 * 1024)
    _run_backup(runner, env, "chain", flag="-D")
    diff_slices = glob.glob(os.path.join(env.backup_dir, f"chain_DIFF_{date}*.1.dar"))
    assert diff_slices, "Expected DIFF archive slice on disk"
    diff_base = os.path.basename(diff_slices[0]).rsplit(".1.dar", 1)[0]
    diff_par2 = _par2_files_in(env.backup_dir, diff_base)
    assert diff_par2, f"Expected par2 files for DIFF archive '{diff_base}'"

    # INCR — add another new file
    _write_random_file(os.path.join(data_dir, "incr_extra.bin"), 128 * 1024)
    _run_backup(runner, env, "chain", flag="-I")
    incr_slices = glob.glob(os.path.join(env.backup_dir, f"chain_INCR_{date}*.1.dar"))
    assert incr_slices, "Expected INCR archive slice on disk"
    incr_base = os.path.basename(incr_slices[0]).rsplit(".1.dar", 1)[0]
    incr_par2 = _par2_files_in(env.backup_dir, incr_base)
    assert incr_par2, f"Expected par2 files for INCR archive '{incr_base}'"

    # All three sets must be distinct
    assert full_base != diff_base != incr_base, (
        "FULL, DIFF, and INCR must produce separate archive bases"
    )


def test_par2_definition_isolation(setup_environment, env: EnvData) -> None:
    """
    Corrupting one definition's archive slice does not invalidate another's par2 set.

    Steps:
      1. Create two definitions ("alpha", "beta") each with its own PAR2_DIR.
      2. Run FULL backups for both.
      3. Corrupt alpha's archive slice.
      4. par2 verify on alpha's par2 index → must fail.
      5. par2 verify on beta's par2 index → must pass.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    overrides: dict[str, dict[str, str]] = {}
    for name in ("alpha", "beta"):
        data_dir = os.path.join(env.test_dir, f"data_{name}")
        par2_dir = os.path.join(env.test_dir, f"par2_{name}")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(par2_dir, exist_ok=True)
        _write_random_file(os.path.join(data_dir, "payload.bin"), 256 * 1024)
        _write_backup_definition(os.path.join(env.backup_d_dir, name), data_dir)
        overrides[name] = {"PAR2_DIR": par2_dir}

    _configure_par2_overrides(env, overrides)
    _create_catalog_db(runner, env)

    for name in ("alpha", "beta"):
        _run_backup(runner, env, name)

    alpha_base = _find_archive_base(env.backup_dir, "alpha", date)
    beta_base = _find_archive_base(env.backup_dir, "beta", date)
    alpha_par2_dir = os.path.join(env.test_dir, "par2_alpha")
    beta_par2_dir = os.path.join(env.test_dir, "par2_beta")

    # Corrupt alpha's archive
    _flip_first_byte(os.path.join(env.backup_dir, f"{alpha_base}.1.dar"))

    import re as _re

    def _slice_par2s(par2_dir, archive_base):
        sp = _re.compile(rf"{_re.escape(archive_base)}\.([0-9]+)\.dar\.par2$")
        return sorted(
            [os.path.join(par2_dir, f) for f in os.listdir(par2_dir) if sp.match(f)],
            key=lambda x: int(_re.search(r"\.(\d+)\.dar\.par2$", x).group(1))
        )

    alpha_par2_files = _slice_par2s(alpha_par2_dir, alpha_base)
    beta_par2_files  = _slice_par2s(beta_par2_dir,  beta_base)

    assert alpha_par2_files, f"No par2 files for alpha in {alpha_par2_dir}"
    assert beta_par2_files,  f"No par2 files for beta in {beta_par2_dir}"

    for p in alpha_par2_files:
        alpha_verify = runner.run(["par2", "verify", "-B", env.backup_dir, p])
        assert alpha_verify.returncode != 0, (
            f"par2 verify must fail for the corrupted alpha archive ({os.path.basename(p)})"
        )

    for p in beta_par2_files:
        beta_verify = runner.run(["par2", "verify", "-B", env.backup_dir, p])
        assert beta_verify.returncode == 0, (
            f"par2 verify must still pass for the untouched beta archive "
            f"({os.path.basename(p)}): {beta_verify.stderr}"
        )


def test_par2_ratio_size_ordering(setup_environment, env: EnvData) -> None:
    """
    A higher PAR2_RATIO_FULL produces a proportionally larger par2 set.

    Two definitions back up the same volume of random (incompressible) data
    with ratios of 5% and 25%.  The par2 set for the 25% definition must be
    meaningfully larger than the one for the 5% definition (at least 1.5×).

    Note: par2 has fixed per-archive overhead (checksums, index packets) that
    is independent of the redundancy level.  For a 1 MB archive this overhead
    dominates, so the observable ratio between the two sets is smaller than the
    raw 5× factor implied by the percentages.  1.5× is a conservative but
    reliable threshold that still catches equal-ratio misconfiguration.

    Steps:
      1. Create two definitions with 1 MB of random data each.
      2. Configure ratio-5 with PAR2_RATIO_FULL=5 and ratio-25 with
         PAR2_RATIO_FULL=25, both with dedicated PAR2_DIRs.
      3. Run FULL backups for both.
      4. Compare total par2 set sizes.
    """
    config_settings = ConfigSettings(env.config_file)
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=config_settings.command_timeout_secs,
    )
    date = datetime.now().strftime("%Y-%m-%d")

    overrides: dict[str, dict[str, str]] = {}
    for name, ratio in (("ratio-5", 5), ("ratio-25", 25)):
        data_dir = os.path.join(env.test_dir, f"data-{name}")
        par2_dir = os.path.join(env.test_dir, f"par2-{name}")
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(par2_dir, exist_ok=True)
        # 1 MB of random bytes — incompressible, gives par2 meaningful data
        _write_random_file(os.path.join(data_dir, "payload.bin"), 1024 * 1024)
        _write_backup_definition(os.path.join(env.backup_d_dir, name), data_dir)
        overrides[name] = {
            "PAR2_DIR": par2_dir,
            "PAR2_RATIO_FULL": str(ratio),
        }

    _configure_par2_overrides(env, overrides)
    _create_catalog_db(runner, env)

    for name in ("ratio-5", "ratio-25"):
        _run_backup(runner, env, name)

    base_5 = _find_archive_base(env.backup_dir, "ratio-5", date)
    base_25 = _find_archive_base(env.backup_dir, "ratio-25", date)
    par2_dir_5 = os.path.join(env.test_dir, "par2-ratio-5")
    par2_dir_25 = os.path.join(env.test_dir, "par2-ratio-25")

    size_5 = _total_par2_size(par2_dir_5, base_5)
    size_25 = _total_par2_size(par2_dir_25, base_25)

    env.logger.info(
        "par2 total sizes — ratio-5: %d bytes, ratio-25: %d bytes", size_5, size_25
    )

    assert size_5 > 0, "Expected non-zero par2 set for ratio-5"
    assert size_25 > 0, "Expected non-zero par2 set for ratio-25"
    assert size_25 >= int(1.5 * size_5), (
        f"Expected ratio-25 par2 set ({size_25} bytes) to be at least 1.5× "
        f"larger than ratio-5 ({size_5} bytes)"
    )
