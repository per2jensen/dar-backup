#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
demo.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/demo.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW,
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to configure dar-backup on your system.
It is non-destructive and will not overwrite any existing files or directories under --override is used.

User can set ROOT_DIR, DIR_TO_BACKUP and BACKUP_DIR (destination for backups) via optins to override defaults.
"""

import argparse
import os
import shutil
import sys

from . import __about__ as about
from . import util

from jinja2 import Environment, FileSystemLoader
from pathlib import Path
from typing import Dict, Optional, Tuple


# demo.py never touches $HOME: everything it creates lives under these 3
# fixed /tmp directories, which --cleanup knows how to remove safely. Ruff's
# hardcoded-tempfile check is suppressed below on purpose: fixed /tmp paths
# are the whole point of this demo tool.
DAR_BACKUP_DIR = util.normalize_dir("/tmp/dar-backup")            # noqa: S108 (backups + log file)
CONFIG_DIR = util.normalize_dir("/tmp/dar-backup-conf")           # noqa: S108 (dar-backup.conf + backup.d/)
DATA_DIR = util.normalize_dir("/tmp/dar-backup-data-dirs")        # noqa: S108 (restore dir + sample data to back up)

# Sample data generated under DATA_DIR/<DIR_TO_BACKUP> by default. The sample
# root itself (DIR_TO_BACKUP, "dir1" by default) is the first of 3 nested
# levels; _SAMPLE_SUBDIRS names the 2 further levels nested beneath it. Each
# level is paired with a small precomputed solid-color JPEG (src/dar_backup/data/)
# so the demo has real, varied content to back up, list, and restore without
# needing an image library at runtime.
_SAMPLE_SUBDIRS: Tuple[str, ...] = ("dir2", "dir3")
_SAMPLE_ASSETS: Tuple[str, ...] = ("sample-red.jpg", "sample-green.jpg", "sample-blue.jpg")



def check_directories(args, vars_map: Dict[str,str]) -> bool:
    """
    Check if target paths already exist and are directories.

    Returns:
        bool: True if it is safe to proceed, False otherwise.
    """
    result = True
    for key in ("DAR_BACKUP_DIR","BACKUP_DIR","TEST_RESTORE_DIR","CONFIG_DIR","BACKUP_D_DIR"):
        path = Path(vars_map[key])
        if path.exists():
            if not path.is_dir():
                print(f"Error: '{path}' exists and is not a directory")
                result = False
                continue
            if not args.override:
                print(f"Directory '{path}' already exists")
                result = False
    return result


def generate_file(args, template: str, file_path: Path, vars_map: Dict[str, str], opts_dict: Dict[str, str]) -> bool:
    """
    Generate a file using a Jinja2 template.

    Args:
        args: Command line arguments.
        template (str): The name of the template file.
        file_path (Path): The path where the generated file will be saved.
        vars_map (Dict[str, str]): A dictionary containing variables for the template.
        opts_dict (Dict[str, str]): A dictionary containing options given by user.

    Returns:
        bool: True if the file was generated successfully, False otherwise.
    """
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    env = Environment(loader=FileSystemLoader(current_script_dir))  # noqa: S701 — renders plain-text config files, not HTML; autoescape would corrupt output
    tpl = env.get_template(template)
    rendered = tpl.render(vars_map = vars_map, opts_dict = opts_dict)
    if rendered is None:
        print(f"Error: Template '{template}' could not be rendered.")
        return False
    if file_path.exists():
        if file_path.is_dir():
            print(f"Error: '{file_path}' is a directory, expected a file.")
            return False
        if not args.override:
            print(f"Error: File '{file_path}' already exists. Use --override to overwrite.")
            return False
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(rendered)
    print(f"File generated at '{file_path}'")
    return True



def generate_sample_data(sample_root: Path, config_file: Path, override: bool) -> bool:
    """
    Populate a 3-level-deep sample directory tree with demo content to back up.

    Each nested level gets a small solid-color JPEG, a text file naming that
    JPEG's path, a symlink to the generated dar-backup.conf, and a hard link
    to the same file — giving `dar-backup --full-backup` real, varied content
    (including links) to archive for the walkthrough.

    Args:
        sample_root: Directory where the sample tree is rooted (ROOT_DIR/DIR_TO_BACKUP);
            this is itself the first of the 3 nested levels.
        config_file: Path to the already-generated dar-backup.conf to link to.
        override: Whether to proceed if sample_root already exists.

    Returns:
        bool: True on success, False if sample_root exists and is not usable.
    """
    if sample_root.exists():
        if not sample_root.is_dir():
            print(f"Error: '{sample_root}' exists and is not a directory")
            return False
        if not override:
            print(f"Directory '{sample_root}' already exists")
            return False

    assets_dir = Path(os.path.dirname(os.path.abspath(__file__))) / "data"

    levels = [sample_root]
    for name in _SAMPLE_SUBDIRS:
        levels.append(levels[-1] / name)

    for level_dir, jpeg_asset in zip(levels, _SAMPLE_ASSETS, strict=True):
        level_dir.mkdir(parents=True, exist_ok=True)

        jpeg_path = level_dir / "color.jpg"
        jpeg_path.write_bytes((assets_dir / jpeg_asset).read_bytes())

        (level_dir / "color.txt").write_text(f"{jpeg_path}\n")

        symlink_path = level_dir / "dar-backup.conf.symlink"
        if symlink_path.is_symlink() or symlink_path.exists():
            symlink_path.unlink()
        symlink_path.symlink_to(config_file)

        hardlink_path = level_dir / "dar-backup.conf.hardlink"
        if hardlink_path.exists():
            hardlink_path.unlink()
        os.link(config_file, hardlink_path)

    print(f"Sample data generated at '{sample_root}'")
    return True


def _resolve_safe(path: str) -> Optional[str]:
    """
    Validate that a demo-managed directory is safe to remove.

    Refuses if `path` itself is a symlink, or if it resolves (via any
    symlinked parent component) to somewhere other than the literal path —
    either case suggests a malicious or unintended link that could otherwise
    redirect a deletion onto unrelated data.

    Args:
        path: Absolute path to validate.

    Returns:
        Optional[str]: The canonical path if safe to remove (or absent), None if unsafe.
    """
    p = Path(path)
    if p.is_symlink():
        print(f"Error: '{path}' is a symlink — refusing to clean up. Remove it manually if intended.")
        return None
    if not p.exists():
        return path
    real = os.path.realpath(path)
    if real != str(p):
        print(f"Error: '{path}' resolves to '{real}' — a parent directory may be a symlink. "
              "Refusing to clean up. Remove it manually if intended.")
        return None
    return real


def cleanup() -> bool:
    """
    Remove the 3 demo directories this tool manages under /tmp.

    All 3 directories are validated before anything is deleted: if any one
    of them fails the safety check, the whole cleanup is aborted and nothing
    is removed, rather than partially deleting the safe ones.

    Returns:
        bool: True if all 3 directories were removed (or already absent), False otherwise.
    """
    targets = (DAR_BACKUP_DIR, CONFIG_DIR, DATA_DIR)
    resolved = [_resolve_safe(target) for target in targets]
    if any(real is None for real in resolved):
        print("Aborting --cleanup: one or more directories failed the safety check; nothing was removed.")
        return False

    for target, real in zip(targets, resolved, strict=True):
        if not Path(target).exists():
            print(f"'{target}' does not exist, nothing to remove.")
            continue
        shutil.rmtree(real)  # type: ignore[arg-type]
        print(f"Removed '{real}'")
    return True


def setup_dicts(args, vars_map: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Override various entries in the dictionaries for jinja templating with user input.

    Returns:
        Tuple[Dict[str, str], Dict[str, str]]: A tuple containing the vars_map and opts_dict dictionaries.
    """
    opts_dict = {}
    if args.root_dir:
        opts_dict["ROOT_DIR"] = args.root_dir
    if args.dir_to_backup:
        opts_dict["DIR_TO_BACKUP"] = args.dir_to_backup
    if args.backup_dir:
        opts_dict["BACKUP_DIR"] = args.backup_dir

    for key, value in opts_dict.items():
        vars_map[key] = value

    return vars_map, opts_dict


def main():
    parser = argparse.ArgumentParser(
        description="Set up demo configuration for `dar-backup` on your system.",
    )
    parser.add_argument(
        "-i", "--install",
        action="store_true",
        help="Deploy demo config files and directories. Will not overwrite existing files or directories unless --override is used."
    )
    req = parser.add_argument_group(
    'These options must be used together'
    )
    req.add_argument(
        "--root-dir",
        type=str,
        help="Specify the root directory for the backup."
    )
    req.add_argument(
        "--dir-to-backup",
        type=str,
        help="Directory to backup, relative to the root directory."
    )
    parser.add_argument(
        "--backup-dir",
        type=str,
        help="Directory where backups and redundancy files are put"
    )
    parser.add_argument(
        "--override",
        action="store_true",
        help="By default, the script will not overwrite existing files or directories. Use this option to override this behavior."
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s version {about.__version__}, {about.__license__}"
    )
    parser.add_argument(
        "-g", "--generate",
        action="store_true",
        help=f"Render the demo config files under '{CONFIG_DIR}' without creating the rest of the demo directories."
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help=f"Remove the demo directories under /tmp ('{DAR_BACKUP_DIR}', '{CONFIG_DIR}', '{DATA_DIR}')."
    )

    args = parser.parse_args()

    group = [args.root_dir, args.dir_to_backup]
    if any(group) and not all(group):
        parser.error(
            "Options --root-dir, --dir-to-backup must all be specified together."
        )

    args.root_dir = util.normalize_dir(util.expand_path(args.root_dir)) if args.root_dir else None
    args.backup_dir = util.normalize_dir(util.expand_path(args.backup_dir)) if args.backup_dir else None
    args.dir_to_backup = util.normalize_dir(util.expand_path(args.dir_to_backup)) if args.dir_to_backup else None



    vars_map = {
    #  dar-backup.conf variables
        "CONFIG_DIR"       : CONFIG_DIR,
        "DAR_BACKUP_DIR"   : DAR_BACKUP_DIR,
        "BACKUP_DIR"       : os.path.join(DAR_BACKUP_DIR, "backups"),
        "BACKUP_D_DIR"     : os.path.join(CONFIG_DIR, "backup.d"),
        "TEST_RESTORE_DIR" : os.path.join(DATA_DIR, "restore"),
    #  backup definition variables
        "ROOT_DIR"         : DATA_DIR,
        "DIR_TO_BACKUP"    : "dir1",
    }


    vars_map, opts_dict = setup_dicts(args, vars_map)

    if args.generate:
        print("Generating backup definition file...")
        args.override = True
        # generate_file() creates each file's parent directory itself.
        generate_file(args, "demo_backup_def.j2", Path(vars_map["BACKUP_D_DIR"]).joinpath("demo"), vars_map, opts_dict)
        generate_file(args, "dar-backup.conf.j2", Path(vars_map["CONFIG_DIR"]).joinpath("dar-backup.conf"), vars_map, opts_dict)
    elif args.install:
        if not check_directories(args, vars_map):
            print("Error: One or more directories already exist.\nSpecify non-existent directories or use --override to overwrite.")
            sys.exit(1)

        Path(vars_map["DAR_BACKUP_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["BACKUP_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["TEST_RESTORE_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["CONFIG_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["BACKUP_D_DIR"]).mkdir(parents=True, exist_ok=True)
        print("Directories created.")

        generate_file(args, "demo_backup_def.j2", Path(vars_map["BACKUP_D_DIR"]).joinpath("demo"), vars_map, opts_dict)
        config_file = Path(vars_map["CONFIG_DIR"]).joinpath("dar-backup.conf")
        config_ok = generate_file(args, "dar-backup.conf.j2", config_file, vars_map, opts_dict)

        using_defaults = args.root_dir is None and args.dir_to_backup is None
        if using_defaults and config_ok:
            sample_root = Path(vars_map["ROOT_DIR"]) / vars_map["DIR_TO_BACKUP"]
            if not generate_sample_data(sample_root, config_file, args.override):
                sys.exit(1)

        print(f"1. Point dar-backup/manager at the demo config: export DAR_BACKUP_CONFIG_FILE={config_file}")
        print("2. Now run `manager --create-db` to create the catalog database.")
        print("3. Then you can run `dar-backup --full-backup` to create a backup.")
        print("4. List backups with `dar-backup --list`")
        print("5. List contents of a backup with `dar-backup --list-contents <backup-name>`")
    elif args.cleanup:
        if not cleanup():
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
