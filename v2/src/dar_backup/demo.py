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
from typing import Dict, Tuple


CONFIG_DIR = util.normalize_dir(util.expand_path("~/.config/dar-backup"))
DAR_BACKUP_DIR = util.normalize_dir(util.expand_path("~/dar-backup"))



def check_directories(args, vars_map: Dict[str,str]) -> bool:
    """
    Check if the directories exist and create them if they don't.

    Returns:
        bool: True if the directories were created successfully, False otherwise.
    """
    result = True
    for key in ("DAR_BACKUP_DIR","BACKUP_DIR","TEST_RESTORE_DIR","CONFIG_DIR","BACKUP_D_DIR"):
        path = Path(vars_map[key])
        if path.exists() and not args.override:
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
    env = Environment(loader=FileSystemLoader(current_script_dir))
    tpl = env.get_template(template)
    rendered = tpl.render(vars_map = vars_map, opts_dict = opts_dict)  
    if rendered is None:
        print(f"Error: Template '{template}' could not be rendered.")
        return False    
    if os.path.exists(file_path) and not args.override:
        print(f"Error: File '{file_path}' already exists. Use --override to overwrite.")
        return False
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(rendered)
    print(f"File generated at '{file_path}'")



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
        help="Generate config files and put them in /tmp/."
    )

    args = parser.parse_args()

    group = [args.root_dir, args.dir_to_backup]
    if any(group) and not all(group):
        parser.error(
            "Options --root-dir, --dir-to-backup must all be specified together."
        )
        exit(1)

    args.root_dir = util.normalize_dir(util.expand_path(args.root_dir)) if args.root_dir else None
    args.backup_dir = util.normalize_dir(util.expand_path(args.backup_dir)) if args.backup_dir else None
    args.dir_to_backup = util.normalize_dir(util.expand_path(args.dir_to_backup)) if args.dir_to_backup else None



    vars_map = {
    #  dar-backup.conf variables 
        "CONFIG_DIR"       : CONFIG_DIR,
        "DAR_BACKUP_DIR"   : DAR_BACKUP_DIR,
        "BACKUP_DIR"       : os.path.join(DAR_BACKUP_DIR, "backups"),
        "BACKUP_D_DIR"     : os.path.join(CONFIG_DIR, "backup.d"),
        "TEST_RESTORE_DIR" : os.path.join(DAR_BACKUP_DIR, "restore"),
    #  backup definition variables
        "ROOT_DIR"         : util.normalize_dir(util.expand_path("$HOME")),
        "DIR_TO_BACKUP"    : ".config/dar-backup",
    } 


    vars_map, opts_dict = setup_dicts(args, vars_map)

    if args.generate:
        print("Generating backup definition file...")
        vars_map["DAR_BACKUP_DIR"] = "/tmp"
        args.override = True
        generate_file(args, "demo_backup_def.j2", Path("/tmp/dar-backup/backup.d/demo"), vars_map, opts_dict)
        vars_map["CONFIG_DIR"] = "/tmp"
        generate_file(args, "dar-backup.conf.j2", Path("/tmp/dar-backup.conf"), vars_map, opts_dict)
    elif args.install:
        if not check_directories(args, vars_map):
            print("Error: One or more directories already exist.\nSpecify non-existent directories or use --override to overwrite.")
            sys.exit(1)

        Path(vars_map["DAR_BACKUP_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["BACKUP_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["TEST_RESTORE_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["CONFIG_DIR"]).mkdir(parents=True, exist_ok=True)
        Path(vars_map["BACKUP_D_DIR"]).mkdir(parents=True, exist_ok=True)
        print(f"Directories created.")

        generate_file(args, "demo_backup_def.j2", Path(vars_map["BACKUP_D_DIR"]).joinpath("demo"), vars_map, opts_dict)
        generate_file(args, "dar-backup.conf.j2", Path(vars_map["CONFIG_DIR"]).joinpath("dar-backup.conf"), vars_map, opts_dict)

        print("1. Now run `manager --create-db` to create the catalog database.")
        print("2. Then you can run `dar-backup --full-backup` to create a backup.")
        print("3. List backups with `dar-backup --list`")
        print("4. List contents of a backup with `dar-backup --list-contents <backup-name>`")
    else:
        parser.print_help()
        sys.exit(1) 

    sys.exit(0)

if __name__ == "__main__":
    main()
