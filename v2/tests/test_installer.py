
import os
import pytest
from  dar_backup.config_settings import ConfigSettings
from dar_backup.installer import run_installer
from dar_backup.manager import get_db_dir
from dar_backup.util import expand_path


@pytest.mark.parametrize("use_manager_db_dir", [False, True])
def test_installer_creates_catalog(setup_environment, env, use_manager_db_dir):
    """
    Integration test: Ensures run_installer creates catalog databases in correct location.
    """
    # Optionally inject MANAGER_DB_DIR
    if use_manager_db_dir:
        custom_catalog_dir = os.path.join(env.test_dir, "catalogs")
        os.makedirs(custom_catalog_dir, exist_ok=True)
        with open(env.config_file, "a") as f:
            f.write(f"\nMANAGER_DB_DIR = {custom_catalog_dir}\n")

    # Create dummy .def file
    backup_def_name = "demo-backup.def"
    backup_def_path = os.path.join(env.backup_d_dir, backup_def_name)
    with open(backup_def_path, "w") as f:
        f.write("fake contents")

    # Run installer (creates the catalogs)
    run_installer(env.config_file, create_db_flag=True, install_ac_flag=False)

    # Load the config settings
    config_settings = ConfigSettings(env.config_file)

    # Determine catalog dir based on config
    catalog_dir = expand_path(get_db_dir(config_settings))
    expected_catalog = os.path.join(catalog_dir, f"{backup_def_name}.db")

    assert os.path.exists(expected_catalog), f"Expected catalog not found: {expected_catalog}"

    # Assert all standard dirs exist
    expected_dirs = [
        env.backup_dir,
        env.backup_d_dir,
        env.restore_dir,
        env.data_dir,
        catalog_dir,
    ]
    for d in expected_dirs:
        assert os.path.isdir(d), f"Expected directory not found: {d}"

