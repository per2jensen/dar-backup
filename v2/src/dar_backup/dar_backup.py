#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
installer.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/installer.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to control `dar` to backup parts of or the whole system.
"""
import argcomplete
import argparse
import filecmp

import os
import random
import re
import shlex
import shutil
import subprocess
import configparser
import xml.etree.ElementTree as ET
import tempfile
import threading

from datetime import datetime
from pathlib import Path
from sys import exit
from sys import stderr
from sys import version_info
from time import time
from rich.console import Console
from rich.text import Text
from typing import Iterable, Iterator, List, Optional, Tuple

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import setup_logging
from dar_backup.util import get_logger
from dar_backup.util import BackupError
from dar_backup.util import RestoreError
from dar_backup.util import requirements
from dar_backup.util import show_version
from dar_backup.util import get_config_file
from dar_backup.util import get_invocation_command_line
from dar_backup.util import get_binary_info
from dar_backup.util import print_aligned_settings
from dar_backup.util import backup_definition_completer, list_archive_completer
from dar_backup.util import show_scriptname
from dar_backup.util import send_discord_message

from dar_backup.command_runner import CommandRunner   



logger = None
runner = None

def generic_backup(type: str, command: List[str], backup_file: str, backup_definition: str, darrc: str,  config_settings: ConfigSettings, args: argparse.Namespace) -> List[str]:
    """
    Performs a backup using the 'dar' command.

    This function initiates a full backup operation by constructing and executing a command
    with the 'dar' utility. It checks if the backup file already exists to avoid overwriting
    previous backups. If the backup file does not exist, it proceeds with the backup operation.

    Args:
        type (str): The type of backup (FULL, DIFF, INCR).
        command (List[str]): The command to execute for the backup operation.
        backup_file (str): The base name of the backup file. The actual backup will be saved
                           as '{backup_file}.1.dar'.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.
        darrc (str): The path to the '.darrc' configuration file.
        config_settings (ConfigSettings): An instance of the ConfigSettings class.


    Raises:
        BackupError: If an error leading to a bad backup occurs during the backup process.

    Returns:
        List of tuples (<msg>, <exit_code>) of errors not considered critical enough for raising an exception  
    """

    result: List[tuple] = []

    logger.info(f"===> Starting {type} backup for {backup_definition}")
    try:
        try:
            process = runner.run(command, timeout=config_settings.command_timeout_secs)
        except Exception as e:
            print(f"[!] Backup failed: {e}")
            raise

        if process.returncode == 0:
            logger.info(f"{type} backup completed successfully.")
        elif process.returncode == 5:
            logger.warning("Backup completed with some files not backed up, this can happen if files are changed/deleted during the backup.")
        else:
            raise Exception(str(process))

        if process.returncode == 0 or process.returncode == 5:
            add_catalog_command = ['manager', '--add-specific-archive' ,backup_file, '--config-file', args.config_file]
            command_result = runner.run(add_catalog_command, timeout = config_settings.command_timeout_secs)
            if command_result.returncode == 0:
                logger.info(f"Catalog for archive '{backup_file}' added successfully to its manager.")
            else:
                msg = f"Catalog for archive '{backup_file}' not added."
                logger.error(msg)
                result.append((msg, 1))

        return result

    except subprocess.CalledProcessError as e:
        logger.error(f"Backup command failed: {e}")
        raise BackupError(f"Backup command failed: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during backup")
        raise BackupError(f"Unexpected error during backup: {e}") from e
    


def find_files_with_paths(xml_doc: str):
    """
    Finds files within an XML element and returns a list of tuples (file path, size).

    Args:
        xml_root: str  The XML generated by dar -l <archive> -Txml.

    Returns:
        list: A list of tuples (file path, size).
    """
    #get_logger().debug("Generating list of tuples with file paths and sizes for File elements in dar xml output")
    xml_doc = re.sub(r'<!DOCTYPE[^>]*>', '', xml_doc)
    root = ET.fromstring(xml_doc)

    files_list = []

    def iterate_dir(element, current_path=""):
        for child in element:
            if child.tag == 'Directory':
                dir_name = child.get('name')
                new_path = f"{current_path}/{dir_name}" if current_path else dir_name
                iterate_dir(child, new_path)

            elif child.tag == 'File':
                file_name = child.get('name')
                file_size = child.get('size')
                file_path = f"{current_path}/{file_name}" if current_path else file_name
                files_list.append((file_path, file_size))

    iterate_dir(root)
    return files_list


class DoctypeStripper:
    """
    File-like wrapper that strips DOCTYPE lines to prevent XXE.
    """
    def __init__(self, path):
        self.f = open(path, "r", encoding="utf-8")
        self.buf = ""
    def read(self, n=-1):
        if n is None or n < 0:
            out = []
            for line in self.f:
                if "<!DOCTYPE" not in line:
                    out.append(line)
            return "".join(out)
        while len(self.buf) < n:
            line = self.f.readline()
            if not line:
                break
            if "<!DOCTYPE" not in line:
                self.buf += line
        result, self.buf = self.buf[:n], self.buf[n:]
        return result


def iter_files_with_paths_from_xml(xml_path: str) -> Iterator[Tuple[str, str]]:
    """
    Stream file paths and sizes from a DAR XML listing to keep memory usage low.
    """
    path_stack: List[str] = []
    # Disable XXE by stripping DOCTYPE
    context = ET.iterparse(DoctypeStripper(xml_path), events=("start", "end"))
    for event, elem in context:
        if event == "start" and elem.tag == "Directory":
            dir_name = elem.get("name")
            if dir_name:
                path_stack.append(dir_name)
        elif event == "end" and elem.tag == "File":
            file_name = elem.get("name")
            file_size = elem.get("size")
            if file_name:
                if path_stack:
                    file_path = "/".join(path_stack + [file_name])
                else:
                    file_path = file_name
                yield (file_path, file_size)
            elem.clear()
        elif event == "end" and elem.tag == "Directory":
            if path_stack:
                path_stack.pop()
            elem.clear()


def find_files_between_min_and_max_size(backed_up_files: Iterable[Tuple[str, str]], config_settings: ConfigSettings):
    """Find files within a specified size range.

    This function takes a list of backed up files, a minimum size in megabytes, and a maximum size in megabytes.
    It iterates through the list of files, converts the file size from the XML to a number, and compares it to the
    specified size range. If a file's size falls within the range, it is added to the result list.

    Args:
        backed_up_files (list): A list of tuples representing backed up files. Each tuple should contain at least
            two elements, where the first element is the file name and the second element is the file size in the
            format "<number> <unit>". For example, ("file.txt", "10 Mio").
        min_size_verification_mb (int): The minimum file size in megabytes.
        max_size_verification_mb (int): The maximum file size in megabytes.

    Returns:
        list: A list of file names that fall within the specified size range.
    """
    logger.debug(f"Finding files in archive between min and max sizes: {config_settings.min_size_verification_mb}MB and {config_settings.max_size_verification_mb}MB")
    files = []
    max_size = config_settings.max_size_verification_mb
    min_size = config_settings.min_size_verification_mb
    dar_sizes = {
        "o"   : 1,
        "kio" : 1024,
        "Mio" : 1024 * 1024,
        "Gio" : 1024 * 1024 * 1024,
        "Tio" : 1024 * 1024 * 1024 * 1024
     }
    pattern = r'(\d+)\s*(\w+)'
    for item in backed_up_files:
        if item is not None and len(item) >= 2  and item[0] is not None and item[1] is not None:
            logger.trace(f"tuple from dar xml list: {item}")
            match = re.match(pattern, item[1])
            if match:
                number = int(match.group(1))
                unit = match.group(2).strip()
                file_size = dar_sizes[unit] * number
                if (min_size * 1024 * 1024) <= file_size <= (max_size * 1024 * 1024):
                    logger.trace(f"File found between min and max sizes: {item}")
                    files.append(item[0])
    return files


def _is_restoretest_candidate(path: str, config_settings: ConfigSettings) -> bool:
    prefixes = [
        prefix.lstrip("/").lower()
        for prefix in getattr(config_settings, "restoretest_exclude_prefixes", [])
    ]
    suffixes = [
        suffix.lower()
        for suffix in getattr(config_settings, "restoretest_exclude_suffixes", [])
    ]
    regex = getattr(config_settings, "restoretest_exclude_regex", None)

    normalized = path.lstrip("/")
    lowered = normalized.lower()
    if prefixes and any(lowered.startswith(prefix) for prefix in prefixes):
        return False
    if suffixes and any(lowered.endswith(suffix) for suffix in suffixes):
        return False
    if regex and regex.search(normalized):
        return False
    return True


def filter_restoretest_candidates(files: List[str], config_settings: ConfigSettings) -> List[str]:
    filtered = [path for path in files if _is_restoretest_candidate(path, config_settings)]
    if logger:
        excluded = len(files) - len(filtered)
        if excluded:
            logger.debug(f"Restore test filter excluded {excluded} of {len(files)} candidates")
    return filtered


def _size_in_verification_range(size_text: str, config_settings: ConfigSettings) -> bool:
    dar_sizes = {
        "o"   : 1,
        "kio" : 1024,
        "Mio" : 1024 * 1024,
        "Gio" : 1024 * 1024 * 1024,
        "Tio" : 1024 * 1024 * 1024 * 1024
     }
    pattern = r'(\d+)\s*(\w+)'
    match = re.match(pattern, size_text or "")
    if not match:
        return False
    unit = match.group(2).strip()
    if unit not in dar_sizes:
        return False
    number = int(match.group(1))
    file_size = dar_sizes[unit] * number
    min_size = config_settings.min_size_verification_mb * 1024 * 1024
    max_size = config_settings.max_size_verification_mb * 1024 * 1024
    return min_size <= file_size <= max_size


def select_restoretest_samples(
    backed_up_files: Iterable[Tuple[str, str]],
    config_settings: ConfigSettings,
    sample_size: int
) -> List[str]:
    if sample_size <= 0:
        return []
    reservoir: List[str] = []
    candidates_seen = 0
    size_filtered_total = 0
    excluded = 0
    for item in backed_up_files:
        if item is None or len(item) < 2:
            continue
        path, size_text = item[0], item[1]
        if not path or not size_text:
            continue
        if not _size_in_verification_range(size_text, config_settings):
            continue
        size_filtered_total += 1
        if not _is_restoretest_candidate(path, config_settings):
            excluded += 1
            continue
        candidates_seen += 1
        if candidates_seen <= sample_size:
            reservoir.append(path)
        else:
            idx = random.randint(1, candidates_seen)
            if idx <= sample_size:
                reservoir[idx - 1] = path
    if logger:
        if size_filtered_total and excluded:
            logger.debug(f"Restore test filter excluded {excluded} of {size_filtered_total} candidates")
        if candidates_seen == 0:
            logger.debug("No restore test candidates found after size/exclude filters")
        elif candidates_seen <= sample_size:
            logger.debug(f"Restore test candidates available: {candidates_seen}, selecting all")
        else:
            logger.debug(f"Restore test candidates available: {candidates_seen}, sampled: {sample_size}")
    return reservoir


def verify(args: argparse.Namespace, backup_file: str, backup_definition: str, config_settings: ConfigSettings):
    """
    Verify the integrity of a DAR backup by performing the following steps:
    1. Run an archive integrity test on the backup file.
    2. Retrieve the list of backed up files.
    3. Find files within def perform_backup(args, ConfigSettings config_settings, backup_d, backup_dir, test_restore_dir, backup_type, min_size_verification_mb, max_size_verification_mb, no_files_verification):file and compare it with the original file.

    Args:
        args (object): Command-line arguments.
        backup_file (str): Path to the DAR backup file.
        backup_definition (str): Path to the backup definition file.
        ConfigSettings (object): An instance of the ConfigSettings class.

    Returns:
        True if the verification process completes successfully, False otherwise.

    Raises:
        Exception: If an error occurs during the verification process.
        PermissionError: If a permission error occurs while comparing files.
    """
    result = True
    command = ['dar', '-t', backup_file, '-N', '-Q']
 
 
    try:
        process = runner.run(command, timeout=config_settings.command_timeout_secs)
    except Exception as e:
        print(f"[!] Backup failed: {e}")
        raise


    if process.returncode == 0:
        logger.info("Archive integrity test passed.")
    else:
        raise Exception(str(process))

    if args.do_not_compare:
        return result

    backed_up_files = get_backed_up_files(
        backup_file,
        config_settings.backup_dir,
        timeout=config_settings.command_timeout_secs
    )

    files = select_restoretest_samples(
        backed_up_files,
        config_settings,
        config_settings.no_files_verification
    )
    if len(files) == 0:
        logger.info(
            "No files eligible for verification after size and restore-test filters, skipping"
        )
        return result

    # find Root path in backup definition
    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logger.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    root_path = None
    for line in backup_definition_content:
        line = line.strip()
        match = re.match(r'^\s*-R\s+(.*)', line)
        if match:
            root_path = match.group(1).strip()
            break
    if root_path is None:
        msg = f"No Root (-R) path found in the backup definition file: '{backup_definition}', restore verification skipped"
        raise BackupError(msg)



    random_files = files

    # Ensure restore directory exists for verification restores
    try:
        os.makedirs(config_settings.test_restore_dir, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"Cannot create restore directory '{config_settings.test_restore_dir}': {exc}") from exc

    for restored_file_path in random_files:
        restore_path = os.path.join(config_settings.test_restore_dir, restored_file_path.lstrip("/"))
        source_path = os.path.join(root_path, restored_file_path.lstrip("/"))
        try:
            if os.path.exists(restore_path):
                try:
                    os.remove(restore_path)
                except OSError:
                    pass
            args.verbose and logger.info(f"Restoring file: '{restored_file_path}' from backup to: '{config_settings.test_restore_dir}' for file comparing")
            command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', config_settings.test_restore_dir, '--noconf',  '-Q', '-B', args.darrc, 'restore-options']
            args.verbose and logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
            process = runner.run(command, timeout = config_settings.command_timeout_secs)    
            if process.returncode != 0:
                raise Exception(str(process))

            if filecmp.cmp(restore_path, source_path, shallow=False):
                args.verbose and logger.info(f"Success: file '{restored_file_path}' matches the original")
            else:
                result = False
                logger.error(f"Failure: file '{restored_file_path}' did not match the original")
        except PermissionError:
            result = False
            logger.exception("Permission error while comparing files, continuing....")
            logger.error("Exception details:", exc_info=True)
        except FileNotFoundError as exc:
            result = False
            missing_path = exc.filename or "unknown path"
            if missing_path == source_path:
                logger.warning(
                    f"Restore verification skipped for '{restored_file_path}': source file missing: '{source_path}'"
                )
            elif missing_path == restore_path:
                logger.warning(
                    f"Restore verification skipped for '{restored_file_path}': restored file missing: '{restore_path}'"
                )
            else:
                logger.warning(
                    f"Restore verification skipped for '{restored_file_path}': file not found: '{missing_path}'"
                )
    return result



def restore_backup(backup_name: str, config_settings: ConfigSettings, restore_dir: str, darrc: str, selection: str =None):
    """
    Restores a backup file to a specified directory.

    Args:
        backup_name (str): The base name of the backup file, without the "slice number.dar"
        backup_dir (str): The directory where the backup file is located.
        restore_dir (str): The directory where the backup should be restored to.
        selection (str, optional): A selection criteria to restore specific files or directories. Defaults to None.
    """
    results: List[tuple] = []
    try:
        backup_file = os.path.join(config_settings.backup_dir, backup_name)
        command = ['dar', '-x', backup_file, '-wa', '-/ Oo', '--noconf', '-Q']
        if "_FULL_" in backup_name:
            command.append('-D')
        if restore_dir:
            if not os.path.exists(restore_dir):
                os.makedirs(restore_dir)
            command.extend(['-R', restore_dir])
        else:
            raise RestoreError("Restore directory ('-R <dir>') not specified")
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        command.extend(['-B', darrc,  'restore-options'])  # the .darrc `restore-options` section
        logger.info(f"Running restore command: {' '.join(map(shlex.quote, command))}")
        process = runner.run(command, timeout = config_settings.command_timeout_secs)
        if process.returncode == 0:
            logger.info(f"Restore completed successfully to: '{restore_dir}'")
        else:
            logger.error(f"Restore command failed: \n ==> stdout: {process.stdout}, \n ==> stderr: {process.stderr}")
            raise RestoreError(str(process))
    except subprocess.CalledProcessError as e:
        raise RestoreError(f"Restore command failed: {e}") from e
    except OSError as e:
        logger.error(f"Failed to create restore directory: {e}")
        raise RestoreError("Could not create restore directory")
    except Exception as e:
        raise RestoreError(f"Unexpected error during restore: {e}") from e

    return results


def get_backed_up_files(backup_name: str, backup_dir: str, timeout: Optional[int] = None) -> Iterable[Tuple[str, str]]:
    """
    Retrieves the list of backed up files from a DAR archive.

    Args:
        backup_name (str): The name of the DAR archive.
        backup_dir (str): The directory where the DAR archive is located.

    Returns:
        Iterable[Tuple[str, str]]: Stream of (file path, size) tuples for all backed up files.
    """
    logger.debug(f"Getting backed up files in xml from DAR archive: '{backup_name}'")
    backup_path = os.path.join(backup_dir, backup_name)
    temp_path = None
    try:
        command = ['dar', '-l', backup_path, '--noconf', '-am', '-as', "-Txml" , '-Q']
        logger.debug(f"Running command: {' '.join(map(shlex.quote, command))}")
        if runner is not None and getattr(runner, "_is_mock_object", False):
            command_result = runner.run(command)
            file_paths = find_files_with_paths(command_result.stdout)
            return file_paths
        stderr_lines: List[str] = []
        with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as temp_file:
            temp_path = temp_file.name
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            def read_stderr():
                if process.stderr is None:
                    return
                for line in process.stderr:
                    stderr_lines.append(line)

            stderr_thread = threading.Thread(target=read_stderr)
            stderr_thread.start()

            if process.stdout is not None:
                for line in process.stdout:
                    if "<!DOCTYPE" in line:
                        continue
                    temp_file.write(line)
            if process.stdout is not None:
                process.stdout.close()

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                stderr_thread.join()
                raise
            stderr_thread.join()

        if process.returncode != 0:
            stderr_text = "".join(stderr_lines)
            logger.error(f"Error listing backed up files from DAR archive: '{backup_name}'")
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning(f"Could not delete temporary file: {temp_path}")
            raise BackupError(
                f"Error listing backed up files from DAR archive: '{backup_name}'"
                f"\nStderr: {stderr_text}"
            )

        def iter_files():
            try:
                for item in iter_files_with_paths_from_xml(temp_path):
                    yield item
            finally:
                try:
                    os.remove(temp_path)
                except OSError:
                    logger.warning(f"Could not delete temporary file: {temp_path}")

        return iter_files()
    except subprocess.CalledProcessError as e:
        logger.error(f"Error listing backed up files from DAR archive: '{backup_name}'")
        raise BackupError(f"Error listing backed up files from DAR archive: '{backup_name}'") from e
    except subprocess.TimeoutExpired as e:
        logger.error(f"Timeout listing backed up files from DAR archive: '{backup_name}'")
        raise BackupError(f"Timeout listing backed up files from DAR archive: '{backup_name}'") from e
    except Exception as e:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning(f"Could not delete temporary file: {temp_path}")
        raise RuntimeError(f"Unexpected error listing backed up files from DAR archive: '{backup_name}'") from e


def list_contents(backup_name, backup_dir, selection=None):
    """
    Lists the contents of a backup.

    Args:
        backup_name (str): The name of the backup.
        backup_dir (str): The directory where the backup is located.
        selection (str, optional): The selection criteria for listing specific contents. Defaults to None.

    Returns:
        None
    """
    backup_path = os.path.join(backup_dir, backup_name)

    try:
        command = ['dar', '-l', backup_path, '--noconf',  '-am', '-as', '-Q']
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        if runner is not None and getattr(runner, "_is_mock_object", False):
            process = runner.run(command)
            stdout,stderr = process.stdout, process.stderr
            if process.returncode != 0:
                (logger or get_logger()).error(f"Error listing contents of backup: '{backup_name}'")
                raise RuntimeError(str(process))
            for line in stdout.splitlines():
                if "[--- REMOVED ENTRY ----]" in line or "[Saved]" in line:
                    print(line)
        else:
            stderr_lines: List[str] = []
            stderr_bytes = 0
            cap = None
            if runner is not None:
                cap = runner.default_capture_limit_bytes
            if not isinstance(cap, int):
                cap = None
            log_path = None
            log_file = None
            log_lock = threading.Lock()
            command_logger = get_logger(command_output_logger=True)
            for handler in getattr(command_logger, "handlers", []):
                if hasattr(handler, "baseFilename"):
                    log_path = handler.baseFilename
                    break
            if log_path:
                log_file = open(log_path, "ab")
                header = (
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - COMMAND: "
                    f"{' '.join(map(shlex.quote, command))}\n"
                ).encode("utf-8", errors="replace")
                log_file.write(header)
                log_file.flush()

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=False,
                bufsize=0
            )

            def read_stderr():
                nonlocal stderr_bytes
                if process.stderr is None:
                    return
                while True:
                    chunk = process.stderr.read(1024)
                    if not chunk:
                        break
                    if log_file:
                        with log_lock:
                            log_file.write(chunk)
                            log_file.flush()
                    if cap is None:
                        stderr_lines.append(chunk)
                    elif cap > 0 and stderr_bytes < cap:
                        remaining = cap - stderr_bytes
                        if len(chunk) <= remaining:
                            stderr_lines.append(chunk)
                            stderr_bytes += len(chunk)
                        else:
                            stderr_lines.append(chunk[:remaining])
                            stderr_bytes = cap

            stderr_thread = threading.Thread(target=read_stderr)
            stderr_thread.start()

            if process.stdout is not None:
                buffer = b""
                while True:
                    chunk = process.stdout.read(1024)
                    if not chunk:
                        break
                    if log_file:
                        with log_lock:
                            log_file.write(chunk)
                    buffer += chunk
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        if b"[--- REMOVED ENTRY ----]" in line or b"[Saved]" in line:
                            print(line.decode("utf-8", errors="replace"))
                process.stdout.close()

            process.wait()
            stderr_thread.join()
            if log_file:
                log_file.close()

            if process.returncode != 0:
                (logger or get_logger()).error(f"Error listing contents of backup: '{backup_name}'")
                stderr_text = "".join(stderr_lines)
                raise RuntimeError(
                    f"Error listing contents of backup: '{backup_name}'"
                    f"\nStderr: {stderr_text}"
                )
    except subprocess.CalledProcessError as e:
        (logger or get_logger()).error(f"Error listing contents of backup: '{backup_name}'")
        raise BackupError(f"Error listing contents of backup: '{backup_name}'") from e  
    except Exception as e:
        raise RuntimeError(f"Unexpected error listing contents of backup: '{backup_name}'") from e  




def create_backup_command(backup_type: str, backup_file: str, darrc: str, backup_definition_path: str, latest_base_backup: str = None) -> List[str]:
    """
    Generate the backup command for the specified backup type.

    Args:
        backup_type (str): The type of backup (FULL, DIFF, INCR).
        backup_file (str): The backup file path. Example: /path/to/example_2021-01-01_FULL
        darrc (str): Path to the .darrc configuration file.
        backup_definition_path (str): Path to the backup definition file.
        latest_base_backup (str, optional): Path to the latest base backup for DIFF or INCR types.

    Returns:
        List[str]: The constructed backup command.
    """
    base_command = ['dar', '-c', backup_file, "-N", '-B', darrc, '-B', backup_definition_path, '-Q', "compress-exclusion", "verbose"]
    
    if backup_type in ['DIFF', 'INCR']:
        if not latest_base_backup:
            raise ValueError(f"Base backup is required for {backup_type} backups.")
        base_command.extend(['-A', latest_base_backup])
    
    return base_command


def validate_required_directories(config_settings: ConfigSettings) -> None:
    """
    Ensure configured directories exist; raise if any are missing.
    """
    required = [
        ("BACKUP_DIR", config_settings.backup_dir),
        ("BACKUP.D_DIR", config_settings.backup_d_dir),
        ("TEST_RESTORE_DIR", config_settings.test_restore_dir),
    ]
    manager_db_dir = getattr(config_settings, "manager_db_dir", None)
    if manager_db_dir:
        required.append(("MANAGER_DB_DIR", manager_db_dir))

    missing = [(name, path) for name, path in required if not path or not os.path.isdir(path)]
    if missing:
        details = "; ".join(f"{name}={path}" for name, path in missing)
        raise RuntimeError(f"Required directories missing or not accessible: {details}")


def preflight_check(args: argparse.Namespace, config_settings: ConfigSettings) -> bool:
    """
    Run preflight checks to validate environment before backup.
    """
    errors = []

    def check_dir(name: str, path: str, require_write: bool = True):
        if not path:
            errors.append(f"{name} is not set")
            return
        if not os.path.isdir(path):
            errors.append(f"{name} does not exist: {path}")
            return
        if require_write and not os.access(path, os.W_OK):
            errors.append(f"{name} is not writable: {path}")

    # Directories and permissions
    check_dir("BACKUP_DIR", config_settings.backup_dir)
    check_dir("BACKUP.D_DIR", config_settings.backup_d_dir)
    check_dir("TEST_RESTORE_DIR", config_settings.test_restore_dir)
    if getattr(config_settings, "manager_db_dir", None):
        check_dir("MANAGER_DB_DIR", config_settings.manager_db_dir)

    # Log directory write access
    log_dir = os.path.dirname(config_settings.logfile_location)
    check_dir("LOGFILE_LOCATION directory", log_dir)

    # Binaries present
    for cmd in ("dar",):
        if shutil.which(cmd) is None:
            errors.append(f"Binary not found on PATH: {cmd}")
    if getattr(config_settings, "par2_enabled", False):
        if shutil.which("par2") is None:
            errors.append("Binary not found on PATH: par2 (required when PAR2.ENABLED is true)")

    # Binaries respond to --version (basic health)
    for cmd in ("dar",):
        if shutil.which(cmd):
            try:
                subprocess.run([cmd, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            except Exception:
                errors.append(f"Failed to run '{cmd} --version'")
    if getattr(config_settings, "par2_enabled", False) and shutil.which("par2"):
        try:
            subprocess.run(["par2", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except Exception:
            errors.append("Failed to run 'par2 --version'")

    # Restore scratch: can create/clean temp file
    scratch_test_file = os.path.join(config_settings.test_restore_dir, ".dar-backup-preflight")
    try:
        os.makedirs(config_settings.test_restore_dir, exist_ok=True)
        with open(scratch_test_file, "w") as f:
            f.write("ok")
        os.remove(scratch_test_file)
    except Exception as exc:
        errors.append(f"Cannot write to TEST_RESTORE_DIR ({config_settings.test_restore_dir}): {exc}")

    # Config sanity: backup definition exists if provided
    if args.backup_definition:
        candidate = os.path.join(config_settings.backup_d_dir, args.backup_definition)
        if not os.path.isfile(candidate):
            errors.append(f"Backup definition not found: {candidate}")

    if errors:
        print("Preflight checks failed:")
        for err in errors:
            print(f" - {err}")
        return False

    if os.environ.get("PYTEST_CURRENT_TEST"):
        print("Preflight checks passed.")

    return True


def perform_backup(args: argparse.Namespace, config_settings: ConfigSettings, backup_type: str, stats_accumulator: list) -> List[str]:
    """
    Perform backup operation.

    Args:
        args: Command-line arguments.
        config_settings: An instance of the ConfigSettings class.
        backup_type: Type of backup (FULL, DIFF, INCR).
        stats_accumulator: List to collect backup statuses.

    Returns:
      List[tuples] - each tuple consists of (<str message>, <exit code>)
    """
    backup_definitions = []
    results: List[tuple] = []

    # Gather backup definitions
    if args.backup_definition:
        if '_' in args.backup_definition:
            msg = f"Skipping backup definition: '{args.backup_definition}' due to '_' in name"
            logger.error(msg)
            results.append((msg, 1))
            return results
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(config_settings.backup_d_dir, args.backup_definition)))
    else:
        for root, _, files in os.walk(config_settings.backup_d_dir):
            for file in files:
                if '_' in file:
                    msg = f"Skipping backup definition: '{file} due to '_' in: name"
                    logger.error(msg)
                    results.append((msg, 1))
                    continue
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        start_len = len(results)
        success = True
        try:
            date = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(config_settings.backup_dir, f"{backup_definition}_{backup_type}_{date}")

            if os.path.exists(backup_file + '.1.dar'):
                msg = f"Backup file {backup_file}.1.dar already exists. Skipping backup [1]."
                logger.warning(msg)
                results.append((msg, 2))
                continue

            latest_base_backup = None
            if backup_type in ['DIFF', 'INCR']:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'

                if args.alternate_reference_archive:
                    latest_base_backup = os.path.join(config_settings.backup_dir, args.alternate_reference_archive)
                    logger.info(f"Using alternate reference archive: {latest_base_backup}")
                    if not os.path.exists(latest_base_backup + '.1.dar'):
                        msg = f"Alternate reference archive: \"{latest_base_backup}.1.dar\" does not exist, skipping..."
                        logger.error(msg)
                        results.append((msg, 1))
                        continue
                else:
                    base_backups = sorted(
                        [f for f in os.listdir(config_settings.backup_dir) if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')],
                        key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                    )
                    if not base_backups:
                        msg = f"No {base_backup_type} backup found for {backup_definition}. Skipping {backup_type} backup."
                        results.append((msg, 1))
                        continue
                    latest_base_backup = os.path.join(config_settings.backup_dir, base_backups[-1].rsplit('.', 2)[0])

            # Generate the backup command
            command = create_backup_command(backup_type, backup_file, args.darrc, backup_definition_path, latest_base_backup)

            # Perform backup
            backup_result = generic_backup(backup_type, command, backup_file, backup_definition_path, args.darrc, config_settings, args)

            if not isinstance(backup_result, list) or not all(isinstance(i, tuple) and len(i) == 2 for i in backup_result):
                logger.error("Unexpected return format from generic_backup")
                backup_result = [("Unexpected return format from generic_backup", 1)]

            results.extend(backup_result)
            logger.info("Starting verification...")
            verify_result = verify(args, backup_file, backup_definition_path, config_settings)
            if verify_result:   
                logger.info("Verification completed successfully.")
            else:
                msg = f"Verification of '{backup_file}' failed."
                logger.error(msg)
                results.append((msg, 2))
            logger.info("Generate par2 redundancy files.")
            generate_par2_files(backup_file, config_settings, args, backup_definition=backup_definition)
            logger.info("par2 files completed successfully.")

        except Exception as e:
            results.append((f"Exception: {e}", 1))
            logger.error(f"Error during {backup_type} backup process for {backup_definition}: {e}", exc_info=True)
            success = False
        finally:
            # Determine status based on new results for this backup definition
            new_results = results[start_len:]
            has_error = any(code == 1 for _, code in new_results)
            has_warning = any(code == 2 for _, code in new_results)
            if has_error:
                success = False

            # Avoid spamming from example/demo backup definitions
            if backup_definition.lower() == "example":
                logger.debug("Skipping stats collection for example backup definition.")
                continue

            if has_error:
                status = "FAILURE"
            elif has_warning:
                status = "WARNING"
            else:
                status = "SUCCESS"
            
            # Aggregate stats instead of sending immediately
            stats_accumulator.append({
                "definition": backup_definition,
                "status": status,
                "type": backup_type,
                "timestamp": datetime.now().strftime("%Y-%m-%d_%H:%M")
            })

    logger.trace(f"perform_backup() results[]: {results}")
    return results

def _parse_archive_base(backup_file: str) -> str:
    return os.path.basename(backup_file)


def _list_dar_slices(archive_dir: str, archive_base: str) -> List[str]:
    pattern = re.compile(rf"{re.escape(archive_base)}\.([0-9]+)\.dar$")
    dar_slices: List[str] = []

    for filename in os.listdir(archive_dir):
        match = pattern.match(filename)
        if match:
            dar_slices.append(filename)

    dar_slices.sort(key=lambda x: int(pattern.match(x).group(1)))
    return dar_slices


def _validate_slice_sequence(dar_slices: List[str], archive_base: str) -> None:
    pattern = re.compile(rf"{re.escape(archive_base)}\.([0-9]+)\.dar$")
    if not dar_slices:
        raise RuntimeError(f"No dar slices found for archive base: {archive_base}")
    slice_numbers = [int(pattern.match(s).group(1)) for s in dar_slices]
    expected = list(range(1, max(slice_numbers) + 1))
    if slice_numbers != expected:
        raise RuntimeError(f"Missing dar slices for archive {archive_base}: expected {expected}, got {slice_numbers}")


def _get_backup_type_from_archive_base(archive_base: str) -> str:
    parts = archive_base.split('_')
    if len(parts) < 3:
        raise RuntimeError(f"Unexpected archive name format: {archive_base}")
    return parts[1]


def _get_par2_ratio(backup_type: str, par2_config: dict, default_ratio: int) -> int:
    backup_type = backup_type.upper()
    if backup_type == "FULL" and par2_config.get("par2_ratio_full") is not None:
        return par2_config["par2_ratio_full"]
    if backup_type == "DIFF" and par2_config.get("par2_ratio_diff") is not None:
        return par2_config["par2_ratio_diff"]
    if backup_type == "INCR" and par2_config.get("par2_ratio_incr") is not None:
        return par2_config["par2_ratio_incr"]
    return default_ratio


def _write_par2_manifest(
    manifest_path: str,
    archive_dir_relative: str,
    archive_base: str,
    archive_files: List[str],
    dar_backup_version: str,
    dar_version: str
) -> None:
    config = configparser.ConfigParser()
    config["MANIFEST"] = {
        "archive_dir_relative": archive_dir_relative,
        "archive_base": archive_base,
        "dar_backup_version": dar_backup_version,
        "dar_version": dar_version,
        "created_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    config["ARCHIVE_FILES"] = {
        "files": "\n".join(archive_files)
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        config.write(f)


def _default_par2_config(config_settings: ConfigSettings) -> dict:
    return {
        "par2_dir": getattr(config_settings, "par2_dir", None),
        "par2_ratio_full": getattr(config_settings, "par2_ratio_full", None),
        "par2_ratio_diff": getattr(config_settings, "par2_ratio_diff", None),
        "par2_ratio_incr": getattr(config_settings, "par2_ratio_incr", None),
        "par2_run_verify": getattr(config_settings, "par2_run_verify", None),
        "par2_enabled": getattr(config_settings, "par2_enabled", True),
    }


def generate_par2_files(backup_file: str, config_settings: ConfigSettings, args, backup_definition: str = None):
    """
    Generate PAR2 files for a given backup file in the specified backup directory.

    Args:
        backup_file (str): The name of the backup file.
        config_settings: The configuration settings object.
        args: The command-line arguments object.
        backup_definition (str): The backup definition name used for per-backup overrides.

    Raises:
        subprocess.CalledProcessError: If the par2 command fails to execute.

    Returns:
        None
    """
    if hasattr(config_settings, "get_par2_config"):
        par2_config = config_settings.get_par2_config(backup_definition)
    else:
        par2_config = _default_par2_config(config_settings)
    if not par2_config.get("par2_enabled", False):
        logger.debug("PAR2 disabled for this backup definition, skipping.")
        return

    archive_dir = config_settings.backup_dir
    archive_base = _parse_archive_base(backup_file)
    backup_type = _get_backup_type_from_archive_base(archive_base)
    par2_dir = par2_config.get("par2_dir")
    if par2_dir:
        par2_dir = os.path.expanduser(os.path.expandvars(par2_dir))
        os.makedirs(par2_dir, exist_ok=True)

    ratio = _get_par2_ratio(backup_type, par2_config, config_settings.error_correction_percent)

    dar_slices = _list_dar_slices(archive_dir, archive_base)
    _validate_slice_sequence(dar_slices, archive_base)
    number_of_slices = len(dar_slices)

    par2_output_dir = par2_dir or archive_dir
    par2_path = os.path.join(par2_output_dir, f"{archive_base}.par2")
    dar_slice_paths = [os.path.join(archive_dir, slice_file) for slice_file in dar_slices]
    logger.info(f"Generating par2 set for archive: {archive_base}")
    command = ['par2', 'create', '-B', archive_dir, f'-r{ratio}', '-q', '-q', par2_path] + dar_slice_paths
    process = runner.run(command, timeout=config_settings.command_timeout_secs)
    if process.returncode != 0:
        logger.error(f"Error generating par2 files for {archive_base}")
        raise subprocess.CalledProcessError(process.returncode, command)

    if par2_dir:
        archive_dir_relative = os.path.relpath(archive_dir, par2_dir)
        manifest_path = f"{par2_path}.manifest.ini"
        _write_par2_manifest(
            manifest_path=manifest_path,
            archive_dir_relative=archive_dir_relative,
            archive_base=archive_base,
            archive_files=dar_slices,
            dar_backup_version=about.__version__,
            dar_version=getattr(args, "dar_version", "unknown")
        )
        logger.info(f"Wrote par2 manifest: {manifest_path}")

    if par2_config.get("par2_run_verify"):
        logger.info(f"Verifying par2 set for archive: {archive_base}")
        verify_command = ['par2', 'verify', '-B', archive_dir, par2_path]
        verify_process = runner.run(verify_command, timeout=config_settings.command_timeout_secs)
        if verify_process.returncode != 0:
            raise subprocess.CalledProcessError(verify_process.returncode, verify_command)
    return


def filter_darrc_file(darrc_path):
    """
    Filters the .darrc file to remove lines containing the options: -vt, -vs, -vd, -vf, and -va.
    The filtered version is stored in a uniquely named file in the home directory of the user running the script.
    The file permissions are set to 440.
    
    Params:
      darrc_path: Path to the original .darrc file.
    
    Raises:
      RuntimeError if something went wrong

    Returns:
      Path to the filtered .darrc file.
    """
    # Define options to filter out
    options_to_remove = {"-vt", "-vs", "-vd", "-vf", "-va"}

    # Get the user's home directory
    home_dir = os.path.expanduser("~")

    # Create a unique file name in the home directory
    filtered_darrc_path = os.path.join(home_dir, f"filtered_darrc_{next(tempfile._get_candidate_names())}.darrc")

    try:
        with open(darrc_path, "r") as infile, open(filtered_darrc_path, "w") as outfile:
            for line in infile:
                # Check if any unwanted option is in the line
                if not any(option in line for option in options_to_remove):
                    outfile.write(line)
        
        # Set file permissions to 440 (read-only for owner and group, no permissions for others)
        os.chmod(filtered_darrc_path, 0o440)

        return filtered_darrc_path

    except Exception as e:
        # If anything goes wrong, clean up the temp file if it was created
        if os.path.exists(filtered_darrc_path):
            os.remove(filtered_darrc_path)
        raise RuntimeError(f"Error filtering .darrc file: {e}")




def show_examples():
    examples = """
FULL back of all backup definitions in backup.d:
  'python3 dar-backup.py  --full-backup'

FULL back of a single backup definition in backup.d
  'python3 dar-backup.py --full-backup -d <name of file in backup.d/>'

DIFF backup (differences to the latest FULL) of all backup definitions:
  'python3 dar-backup.py --differential-backup'

DIFF back of a single backup definition in backup.d
  'python3 dar-backup.py --differential-backup -d <name of file in backup.d/>'
  
INCR backup (differences to the latest DIFF) of all backup definitions:
  'python3 dar-backup.py --incremental-backup'

INCR back of a single backup definition in backup.d
  'python3 dar-backup.py --incremental-backup -d <name of file in backup.d/>'
  
--alternate-reference-archive (useful if the calculated archive is broken)
    Use this to specify a different reference archive for DIFF or INCR backups.
    The specified archive can be any regardsless of type,  name does not include the slice number.
    Example: 'python3 dar-backup.py --differential-backup --alternate-reference-archive <name of dar archive>'

--log-level
    "trace" logs output from programs (typically dar and par2) run in a subprocess
    "debug" logs various statuses and notices to better understand how to script works


--selection

    --selection takes dar file selection options inside a quoted string.
    
    💡 Shell quoting matters! Always wrap the entire selection string in double quotes to avoid shell splitting. 

    ✅ Use:   --selection="-I '*.NEF'"
    ❌ Avoid: --selection "-I '*.NEF'" → may break due to how your shell parses it.

    Examples:
    1)
    select file names with "Z50_" in file names:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-I '*Z50_*'"
    2)
    Filter out *.xmp files:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-X '*.xmp'"
    
    3)
    Include all files in a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-g 'path/to/a/dir'"

    4)
    Exclude a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-P 'path/to/a/dir'"

    See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)



def print_markdown(source: str, from_string: bool = False, pretty: bool = True):
    """
    Print Markdown content either from a file or directly from a string.
    
    Args:
        source: Path to the file or Markdown string itself.
        from_string: If True, treat `source` as Markdown string instead of file path.
        pretty: If True, render with rich formatting if available.
    """
    import os
    import sys

    content = ""
    if from_string:
        content = source
    else:
        if not os.path.exists(source):
            print(f"❌ File not found: {source}")
            sys.exit(1)
        with open(source, "r", encoding="utf-8") as f:
            content = f.read()

    if pretty:
        try:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.print(Markdown(content))
        except ImportError:
            print("⚠️ 'rich' not installed. Falling back to plain text.\n")
            print(content)
    else:
        print(content)



def print_changelog(path: str = None, pretty: bool = True):
    if path is None:
        path = Path(__file__).parent / "Changelog.md"
    print_markdown(str(path), pretty=pretty)


def print_readme(path: str = None, pretty: bool = True):
    if path is None:
        path = Path(__file__).parent / "README.md"
    print_markdown(str(path), pretty=pretty)

def list_definitions(backup_d_dir: str) -> List[str]:
    """
    Return backup definition filenames from BACKUP.D_DIR, sorted by name.
    """
    dir_path = Path(backup_d_dir)
    if not dir_path.is_dir():
        raise RuntimeError(f"BACKUP.D_DIR does not exist or is not a directory: {backup_d_dir}")
    return sorted([entry.name for entry in dir_path.iterdir() if entry.is_file()])


def clean_restore_test_directory(config_settings: ConfigSettings):
    """
    Cleans up the restore test directory to ensure a clean slate.
    """
    restore_dir = getattr(config_settings, "test_restore_dir", None)
    if not restore_dir:
        return

    restore_dir = os.path.expanduser(os.path.expandvars(restore_dir))
    
    if not os.path.exists(restore_dir):
        return

    # Safety: Do not delete if it resolves to a critical path
    critical_paths = ["/", "/home", "/root", "/usr", "/var", "/etc", "/tmp", "/opt", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/run"]
    normalized = os.path.realpath(restore_dir)
    
    # Check exact matches
    if normalized in critical_paths:
        logger.warning(f"Refusing to clean critical directory: {normalized}")
        return
        
    # Check if it's the user's home directory
    home = os.path.expanduser("~")
    if normalized == home:
        logger.warning(f"Refusing to clean user home directory: {normalized}")
        return

    logger.debug(f"Cleaning restore test directory: {restore_dir}")
    try:
        for item in os.listdir(restore_dir):
            item_path = os.path.join(restore_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                logger.warning(f"Failed to remove {item_path}: {e}")
    except Exception as e:
        logger.warning(f"Failed to clean restore directory {restore_dir}: {e}")


def main():
    global logger, runner
    results: List[(str,int)] = []  # a list op tuples (<msg>, <exit code>)

    MIN_PYTHON_VERSION = (3, 9)
    if version_info < MIN_PYTHON_VERSION:
        stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        exit(1)

    parser = argparse.ArgumentParser(description="Backup, verify & redundancy using dar and par2.")
    parser.add_argument('-F', '--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('-D', '--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('-I', '--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.").completer = backup_definition_completer
    parser.add_argument('--alternate-reference-archive', help="DIFF or INCR compared to specified archive.").completer = list_archive_completer
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default=None)
    parser.add_argument('--darrc', type=str, help='Optional path to .darrc')
    parser.add_argument(
        '-l',
        '--list',
        nargs='?',
        const=True,
        default=False,
        help="List available archives.",
    ).completer = list_archive_completer
    parser.add_argument('--list-contents', help="List the contents of the specified archive.").completer = list_archive_completer
    parser.add_argument('--list-definitions', action='store_true', help="List available backup definitions from BACKUP.D_DIR.")
    parser.add_argument('--selection', type=str, help="Selection string to pass to 'dar', e.g. --selection=\"-I '*.NEF'\"")
#    parser.add_argument('-r', '--restore', nargs=1, type=str, help="Restore specified archive.")
    parser.add_argument('-r', '--restore', type=str, help="Restore specified archive.").completer = list_archive_completer
    parser.add_argument('--restore-dir',   type=str, help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--preflight-check', action='store_true', help="Run preflight checks and exit")
    parser.add_argument('--suppress-dar-msg', action='store_true', help="cancel dar options in .darrc: -vt, -vs, -vd, -vf and -va")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument("--readme", action="store_true", help="Print README.md to stdout and exit.")
    parser.add_argument("--readme-pretty", action="store_true", help="Print README.md to stdout with Markdown styling and exit.")
    parser.add_argument("--changelog", action="store_true", help="Print Changelog.md to stdout and exit.")
    parser.add_argument("--changelog-pretty", action="store_true", help="Print Changelog.md to stdout with Markdown styling and exit.")
    parser.add_argument('-v', '--version', action='store_true', help="Show version and license information.")
    
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    # Ensure new flags are present when parse_args is mocked in tests
    if not hasattr(args, "preflight_check"):
        args.preflight_check = False
    if not hasattr(args, "list_definitions"):
        args.list_definitions = False

    if args.version:
        show_version()
        exit(0)
    elif args.examples:
        show_examples()
        exit(0)
    elif args.readme:
        print_readme(None, pretty=False)
        exit(0)
    elif args.readme_pretty:
        print_readme(None, pretty=True)
        exit(0)
    elif args.changelog:
        print_changelog(None, pretty=False)
        exit(0)
    elif args.changelog_pretty:
        print_changelog(None, pretty=True)
        exit(0)


    # be backwards compatible with older versions
    DEFAULT_CONFIG_FILE = "~/.config/dar-backup/dar-backup.conf"

    env_cf = os.getenv("DAR_BACKUP_CONFIG_FILE")
    env_cf = env_cf.strip() if env_cf else None

    cli_cf = args.config_file.strip() if args.config_file else None
    
    raw_config = (
        cli_cf
        or env_cf
        or DEFAULT_CONFIG_FILE
    )

    config_settings_path = get_config_file(args)

    if not (os.path.isfile(config_settings_path) and os.access(config_settings_path, os.R_OK)):
        print(f"Config file {config_settings_path} must exist and be readable.", file=stderr)
        raise SystemExit(127)

    args.config_file = config_settings_path
    try:
        config_settings = ConfigSettings(args.config_file)
    except Exception as exc:
        msg = f"Config error: {exc}"
        print(msg, file=stderr)
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - {msg}")
        exit(127)

    if args.list_definitions:
        try:
            for name in list_definitions(config_settings.backup_d_dir):
                print(name)
        except RuntimeError as exc:
            print(str(exc), file=stderr)
            exit(127)
        exit(0)

    try:
        validate_required_directories(config_settings)
    except RuntimeError as exc:
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - {exc}", config_settings=config_settings)
        print(str(exc), file=stderr)
        exit(127)

    # Run preflight checks always; if --preflight-check is set, exit afterward.
    ok = preflight_check(args, config_settings)
    if not ok:
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - preflight checks failed", config_settings=config_settings)
        exit_code = 127 if args.backup_definition else 1
        exit(exit_code)
    if args.preflight_check:
        exit(0)

    command_output_log = config_settings.logfile_location.replace("dar-backup.log", "dar-backup-commands.log")
    if command_output_log == config_settings.logfile_location:
        print(f"Error: logfile_location in {args.config_file} does not end at 'dar-backup.log', exiting", file=stderr)

    logger = setup_logging(
        config_settings.logfile_location,
        command_output_log,
        args.log_level,
        args.log_stdout,
        logfile_max_bytes=config_settings.logfile_max_bytes,
        logfile_backup_count=config_settings.logfile_backup_count,
        trace_log_max_bytes=getattr(config_settings, "trace_log_max_bytes", 10485760),
        trace_log_backup_count=getattr(config_settings, "trace_log_backup_count", 1)
    )
    command_logger = get_logger(command_output_logger = True)
    runner = CommandRunner(
        logger=logger,
        command_logger=command_logger,
        default_capture_limit_bytes=getattr(config_settings, "command_capture_max_bytes", None)
    )

    clean_restore_test_directory(config_settings)


    try:
        if not args.darrc:
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            args.darrc = os.path.join(current_script_dir, ".darrc")

        darrc_file = os.path.expanduser(os.path.expandvars(args.darrc))
        if os.path.exists(darrc_file) and os.path.isfile(darrc_file):
            logger.debug(f"Using .darrc: {args.darrc}")                
        else:
            logger.error(f"Supplied .darrc: '{args.darrc}' does not exist or is not a file, exiting", file=stderr)
            exit(127)

        if args.suppress_dar_msg:
            logger.info("Suppressing dar messages, do not use options: -vt, -vs, -vd, -vf, -va")
            args.darrc = filter_darrc_file(args.darrc)
            logger.debug(f"Filtered .darrc file: {args.darrc}")

        start_msgs: List[Tuple[str, str]] = []

        start_time=int(time())
        start_msgs.append((f"{show_scriptname()}:", about.__version__))
        logger.info(f"START TIME: {start_time}")
        logger.debug(f"Command line:\n{get_invocation_command_line()}")
        logger.debug(f"`Args`:\n{args}")
        logger.debug(f"`Config_settings`:\n{config_settings}")
        dar_properties = get_binary_info(command='dar')
        args.dar_version = dar_properties.get('version', 'unknown')
        start_msgs.append(('dar path:', dar_properties['path']))
        start_msgs.append(('dar version:', dar_properties['version']))

        file_dir =  os.path.normpath(os.path.dirname(__file__))
        start_msgs.append(('Script directory:', os.path.abspath(file_dir)))
        start_msgs.append(('Config file:', os.path.abspath(args.config_file)))
        start_msgs.append((".darrc location:", args.darrc))

        args.full_backup         and start_msgs.append(("Type of backup:", "FULL"))
        args.differential_backup and start_msgs.append(("Type of backup:", "DIFF"))
        args.incremental_backup  and start_msgs.append(("Type of backup:", "INCR"))
        args.verbose and args.backup_definition   and start_msgs.append(("Backup definition:", args.backup_definition))
        if args.alternate_reference_archive:
            args.verbose and start_msgs.append(("Alternate ref archive:", args.alternate_reference_archive))
        args.verbose and start_msgs.append(("Backup.d dir:", config_settings.backup_d_dir))
        args.verbose and start_msgs.append(("Backup dir:", config_settings.backup_dir))

        restore_dir = args.restore_dir if args.restore_dir else config_settings.test_restore_dir
        args.verbose and start_msgs.append(("Restore dir:", restore_dir))

        args.verbose and start_msgs.append(("Logfile location:", config_settings.logfile_location))
        args.verbose and start_msgs.append(("Logfile max size (bytes):", config_settings.logfile_max_bytes))
        args.verbose and start_msgs.append(("Logfile backup count:", config_settings.logfile_backup_count))

        args.verbose and start_msgs.append(("PAR2 enabled:", config_settings.par2_enabled))
        args.verbose and start_msgs.append(("--do-not-compare:", args.do_not_compare))

        highlight_keywords = ["--do-not", "alternate"] # TODO: add more dangerous keywords
        print_aligned_settings(start_msgs, quiet=not args.verbose, highlight_keywords=highlight_keywords)

        # sanity check
        if args.backup_definition and not os.path.exists(os.path.join(config_settings.backup_d_dir, args.backup_definition)):
            logger.error(f"Backup definition: '{args.backup_definition}' does not exist, exiting")
            exit(127)
        if args.backup_definition and '_' in args.backup_definition:
            logger.error(f"Backup definition: '{args.backup_definition}' contains '_', exiting")
            exit(1)


        requirements('PREREQ', config_settings)

        stats: List[dict] = []

        if args.list:
            list_filter = args.backup_definition
            if isinstance(args.list, str):
                if list_filter:
                    if args.list.startswith(list_filter):
                        list_filter = args.list
                else:
                    list_filter = args.list
            list_backups(config_settings.backup_dir, list_filter)
        elif args.full_backup and not args.differential_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "FULL", stats))
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "DIFF", stats))
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            results.extend(perform_backup(args, config_settings, "INCR", stats))
            logger.debug(f"results from perform_backup(): {results}")
        elif args.list_contents:
            list_contents(args.list_contents, config_settings.backup_dir, args.selection)
        elif args.restore:
            logger.debug(f"Restoring {args.restore} to {restore_dir}")
            results.extend(restore_backup(args.restore, config_settings, restore_dir, args.darrc, args.selection))
        else:
            parser.print_help()

        logger.debug(f"results[]: {results}")

        # Send aggregated Discord notification if stats were collected
        if stats:
            total = len(stats)
            failures = [s for s in stats if s['status'] == 'FAILURE']
            warnings = [s for s in stats if s['status'] == 'WARNING']
            successes = [s for s in stats if s['status'] == 'SUCCESS']
            
            ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
            
            if failures or warnings:
                msg_lines = [f"{ts} - dar-backup Run Completed"]
                msg_lines.append(f"Total: {total}, Success: {len(successes)}, Warning: {len(warnings)}, Failure: {len(failures)}")
                
                if failures:
                    msg_lines.append("\nFailures:")
                    for f in failures:
                        msg_lines.append(f"- {f['definition']} ({f['type']})")
                
                if warnings:
                    msg_lines.append("\nWarnings:")
                    for w in warnings:
                        msg_lines.append(f"- {w['definition']} ({w['type']})")
                
                send_discord_message("\n".join(msg_lines), config_settings=config_settings)
            else:
                # All successful
                send_discord_message(f"{ts} - dar-backup: SUCCESS - All {total} backups completed successfully.", config_settings=config_settings)

        requirements('POSTREQ', config_settings)


    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.error(msg, exc_info=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - {msg}", config_settings=config_settings)
        results.append((repr(e), 1))
    finally:
        end_time=int(time())
        logger.info(f"END TIME: {end_time}")
        # Clean up
        if os.path.exists(args.darrc) and (os.path.dirname(args.darrc) == os.path.expanduser("~")):
            if os.path.basename(args.darrc).startswith("filtered_darrc_"):
                if os.remove(args.darrc):
                    logger.debug(f"Removed filtered .darrc: {args.darrc}")


    # Determine exit code 
    error = False
    final_exit_code = 0
    logger.debug(f"results[]: {results}")
    if results:
        i = 0
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                msg, exit_code = result
                logger.debug(f"exit code: {exit_code}, msg: {msg}")
                if exit_code > 0:
                    error = True
                    args.verbose and print(msg)
                    if exit_code == 1:
                        final_exit_code = 1
                    elif exit_code == 2 and final_exit_code == 0:
                        final_exit_code = 2
            else:
                logger.error(f"not correct result type: {result}, which must be a tuple (<msg>, <exit_code>)")
                error = True
                final_exit_code = 1
            i=i+1
            
    console = Console()
    if error:
        if args.verbose:
            console.print(Text("Errors encountered", style="bold red"))
        exit(final_exit_code or 1)
    else:
        if args.verbose:
            console.print(Text("Success: all backups completed", style="bold green"))
        exit(0)

    
if __name__ == "__main__":
    main()
