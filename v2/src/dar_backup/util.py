# SPDX-License-Identifier: GPL-3.0-or-later

"""
util.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file
"""
import typing
import inspect
import logging
import json
import sqlite3
from contextlib import closing

import os
import re
import subprocess
import shlex
import shutil
import sys
import tempfile
import threading
import traceback
import urllib.error
import urllib.request

import dar_backup.__about__ as about



from datetime import datetime, date
from dar_backup.config_settings import ConfigSettings
from logging.handlers import RotatingFileHandler
from pathlib import Path
from rich.console import Console
from rich.text import Text

from typing import List
from typing import Tuple


logger=None
secondary_logger=None   


def _reset_logger_handlers(target_logger: logging.Logger) -> None:
    for handler in list(target_logger.handlers):
        target_logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass


def _setup_logging_fallback(exc: Exception) -> logging.Logger:
    global logger, secondary_logger

    logger = logging.getLogger("main_logger")
    secondary_logger = logging.getLogger("command_output_logger")
    _reset_logger_handlers(logger)
    _reset_logger_handlers(secondary_logger)
    logger.setLevel(logging.DEBUG)
    secondary_logger.setLevel(logging.DEBUG)
    logger.propagate = True
    secondary_logger.propagate = True

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    try:
        main_log = tempfile.NamedTemporaryFile(prefix="dar-backup-fallback-main-", suffix=".log", delete=False)
        command_log = tempfile.NamedTemporaryFile(prefix="dar-backup-fallback-command-", suffix=".log", delete=False)
        main_log.close()
        command_log.close()

        main_handler = logging.FileHandler(main_log.name, encoding="utf-8")
        command_handler = logging.FileHandler(command_log.name, encoding="utf-8")
        stderr_handler = logging.StreamHandler(sys.stderr)

        main_handler.setFormatter(formatter)
        command_handler.setFormatter(formatter)
        stderr_handler.setFormatter(formatter)
        stderr_handler.setLevel(logging.WARNING)

        logger.addHandler(main_handler)
        logger.addHandler(stderr_handler)
        secondary_logger.addHandler(command_handler)

        print(
            "[WARN] Logging initialization failed; continuing with fallback log files:\n"
            f"  Main log: {main_log.name}\n"
            f"  Command log: {command_log.name}",
            file=sys.stderr,
        )
    except Exception:
        main_stderr_handler = logging.StreamHandler(sys.stderr)
        command_stderr_handler = logging.StreamHandler(sys.stderr)
        main_stderr_handler.setFormatter(formatter)
        command_stderr_handler.setFormatter(formatter)
        logger.addHandler(main_stderr_handler)
        secondary_logger.addHandler(command_stderr_handler)
        print(
            "[WARN] Logging initialization failed; continuing with stderr-only fallback logging.",
            file=sys.stderr,
        )

    logger.error("Logging initialization failed: %s", exc, exc_info=True)
    secondary_logger.warning("Command output logger running in fallback mode.")
    return logger

class CleanFormatter(logging.Formatter):
    """
    Formatter that ignores exception tracebacks.
    """
    def format(self, record):
        # Save original exception info
        orig_exc_info = record.exc_info
        orig_exc_text = record.exc_text
        
        # Temporarily hide it
        record.exc_info = None
        record.exc_text = None
        
        try:
            return super().format(record)
        finally:
            # Restore it so other handlers (like the trace handler) can use it
            record.exc_info = orig_exc_info
            record.exc_text = orig_exc_text

#def setup_logging(log_file: str, command_output_log_file: str, log_level: str = "info", log_to_stdout: bool = False) -> logging.Logger:
def setup_logging(
    log_file: str,
    command_output_log_file: str,
    log_level: str = "info",
    log_to_stdout: bool = False,
    logfile_max_bytes: int = 26214400,
    logfile_backup_count: int = 5,
    trace_log_file: str = None,
    trace_log_max_bytes: int = 10485760,
    trace_log_backup_count: int = 1
) -> logging.Logger:

    """
    Sets up logging for the main program and a separate secondary logfile for command outputs.
    
    Also sets up a trace log file that captures all logs at DEBUG level including stack traces.

    Args:
        log_file (str): The path to the main log file.
        command_output_log_file (str): The path to the secondary log file for command outputs.
        log_level (str): The log level to use. Can be "info", "debug", or "trace". Defaults to "info".
        log_to_stdout (bool): If True, log messages will be printed to the console. Defaults to False.
        logfile_max_bytes: max file size of a log file, defailt = 26214400.
        logfile_backup_count: max numbers of logs files, default = 5.
        trace_log_file (str): Optional path for the trace log file. Defaults to log_file with ".trace.log" suffix.
        trace_log_max_bytes: max file size of the trace log file, default = 10485760 (10MB).
        trace_log_backup_count: max numbers of trace log files, default = 1.

    Returns:
        a RotatingFileHandler logger instance.

    Raises:
        Exception: If an error occurs during logging initialization
    """
    global logger, secondary_logger
    try:
        TRACE_LEVEL_NUM = 5
        logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

        def trace(self, message, *args, **kws):
            if self.isEnabledFor(TRACE_LEVEL_NUM):
                self.log(TRACE_LEVEL_NUM, message, *args, **kws)

        logging.Logger.trace = trace

        # Main log file handler (clean logs)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=logfile_max_bytes,
            backupCount=logfile_backup_count,
            encoding="utf-8",
        )

        # Trace log file handler (full details)
        if not trace_log_file:
            if log_file == "/dev/null":
                trace_log_file = "/dev/null"
            else:
                base, ext = os.path.splitext(log_file)
                trace_log_file = f"{base}.trace{ext}"
            
        trace_handler = RotatingFileHandler(
            trace_log_file,
            maxBytes=trace_log_max_bytes,
            backupCount=trace_log_backup_count,
            encoding="utf-8",
        )
        # Trace handler gets everything (DEBUG level) and keeps tracebacks
        trace_handler.setLevel(logging.DEBUG)

        command_handler = RotatingFileHandler(
            command_output_log_file,
            maxBytes=logfile_max_bytes,
            backupCount=logfile_backup_count,
            encoding="utf-8",
        )

        standard_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        clean_formatter = CleanFormatter('%(asctime)s - %(levelname)s - %(message)s')
        
        file_handler.setFormatter(clean_formatter)
        trace_handler.setFormatter(standard_formatter)
        command_handler.setFormatter(standard_formatter)


        # Setup main logger
        logger = logging.getLogger("main_logger")
        # Remove handlers left by any previous setup_logging call so stale
        # file handles (e.g. from a prior test's tmp directory) cannot
        # accumulate and cause FileNotFoundError on the next log write.
        for _h in list(logger.handlers):
            _h.close()
            logger.removeHandler(_h)
        # Ensure logger captures everything so trace_handler can see DEBUG messages even if main log_level is INFO
        logger.setLevel(logging.DEBUG)
        logger.propagate = True

        # Configure file_handler level based on user preference
        file_handler.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)

        logger.addHandler(file_handler)
        logger.addHandler(trace_handler)

        # Setup secondary logger for command outputs
        secondary_logger = logging.getLogger("command_output_logger")
        for _h in list(secondary_logger.handlers):
            _h.close()
            secondary_logger.removeHandler(_h)
        secondary_logger.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
        secondary_logger.propagate = True
        secondary_logger.addHandler(command_handler)
        secondary_logger.addHandler(trace_handler)

        if log_to_stdout:
            _out = sys.stdout
            enc = (getattr(_out, 'encoding', None) or 'utf-8').lower().replace('-', '')
            if enc not in ('utf8', 'utf16', 'utf32') and hasattr(_out, 'reconfigure'):
                try:
                    _out.reconfigure(encoding='utf-8', errors='replace')
                except Exception:
                    pass
            stdout_handler = logging.StreamHandler(_out)
            stdout_handler.setFormatter(clean_formatter)
            stdout_handler.setLevel(logging.DEBUG if log_level == "debug" else TRACE_LEVEL_NUM if log_level == "trace" else logging.INFO)
            logger.addHandler(stdout_handler)

        return logger
    except Exception as exc:
        traceback.print_exc()
        return _setup_logging_fallback(exc)


def derive_trace_log_path(log_file: str) -> str:
    if log_file == "/dev/null":
        return "/dev/null"
    base, ext = os.path.splitext(log_file)
    return f"{base}.trace{ext}"



def get_logger(command_output_logger: bool = False) -> logging.Logger:
    """
    Returns a logger

    Args:
        use_secondary (bool): If True, returns the secondary logger. Defaults to False.

    Returns:
      logger to dar-backup.log or the logger for command output.
    """
    global logger, secondary_logger

    return secondary_logger if command_output_logger else logger


def _default_completer_logfile() -> str:
    try:
        uid = os.getuid()
    except AttributeError:
        uid = None
    suffix = str(uid) if uid is not None else "unknown"
    return f"/tmp/dar_backup_completer_{suffix}.log"


# Setup completer logger only once
def _setup_completer_logger(logfile: str = None):
    logger = logging.getLogger("completer")
    if not logger.handlers:
        try:
            logfile = logfile or _default_completer_logfile()
            handler = logging.FileHandler(logfile)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)
        except Exception:
            logger.addHandler(logging.NullHandler())
            logger.setLevel(logging.DEBUG)
    return logger

# Singleton logger for completer debugging
completer_logger = _setup_completer_logger()
completer_logger.debug("Completer logger initialized.")


def print_debug(msg):
    """
    Print a debug message with the filename and line number of the caller.    
    """
    frame = inspect.currentframe().f_back
    print(f"[DEBUG] {frame.f_code.co_filename}:{frame.f_lineno} - {repr(msg)}")



def get_invocation_command_line() -> str:
    """
    Safely retrieves the exact command line used to invoke the current Python process.

    On Unix-like systems, this reads from /proc/[pid]/cmdline to reconstruct the
    command with interpreter and arguments. If any error occurs (e.g., file not found,
    permission denied, non-Unix platform), it returns a descriptive error message.

    Returns:
        str: The full command line string, or an error description if it cannot be retrieved.
    """
    try:
        cmdline_path = f"/proc/{os.getpid()}/cmdline"
        with open(cmdline_path, "rb") as f:
            content = f.read()
            if not content:
                return "[error: /proc/cmdline is empty]"
            return content.replace(b'\x00', b' ').decode().strip()
    except Exception as e:
        return f"[error: could not read /proc/[pid]/cmdline: {e}]"


def show_scriptname()  -> str:
    """
    Return script name, useful in start banner for example
    """
    try:
        scriptname = os.path.basename(sys.argv[0])
    except Exception:
        scriptname = "unknown"
    return scriptname


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {about.__version__}")
    print(f"{script_name} source code is here: https://github.com/per2jensen/dar-backup")
    print(about.__license__)


def render_discord_report(
    start_time: str,
    end_time: str,
    backups: list,
    prereqs: dict,
    postreqs: dict,
) -> str:
    """
    Render the Discord backup report from the bundled Jinja2 template.

    Args:
        start_time: ISO-8601 timestamp for the start of the run.
        end_time: ISO-8601 timestamp for the end of the run.
        backups: List of backup stat dicts (pre-sorted by definition name).
        prereqs: PREREQ result dict with 'status' and 'failures' keys.
        postreqs: POSTREQ result dict with 'status' and 'failures' keys.

    Returns:
        Rendered report string ready to send to Discord.
    """
    import importlib.resources as pkg_resources
    from jinja2 import Environment, BaseLoader

    ref = pkg_resources.files("dar_backup.data").joinpath("discord_report.j2")
    with pkg_resources.as_file(ref) as p:
        template_text = p.read_text(encoding="utf-8")

    env = Environment(
        loader=BaseLoader(),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    template = env.from_string(template_text)
    return template.render(
        start_time=start_time,
        end_time=end_time,
        backups=backups,
        prereqs=prereqs,
        postreqs=postreqs,
    )


def send_discord_message(
    content: str,
    config_settings: typing.Optional[ConfigSettings] = None,
    timeout_seconds: int = 10
) -> bool:
    """
    Send a message to a Discord webhook if configured either in the config file or via environment.

    The environment varible DAR_BACKUP_DISCORD_WEBHOOK_URL, when set, takes precedence over the config file variable 
    with the same name. If neither is defined, the function logs an info-level message and returns False.

    Returns:
        bool: True if the message was sent successfully, otherwise False.
    """
    log = get_logger()

    config_webhook = getattr(config_settings, "dar_backup_discord_webhook_url", None) if config_settings else None
    env_webhook = os.environ.get("DAR_BACKUP_DISCORD_WEBHOOK_URL")

    webhook_url = env_webhook or config_webhook
    source = "environment" if env_webhook else ("config file" if config_webhook else None)

    if not webhook_url:
        log and log.info("Discord message not sent: DAR_BACKUP_DISCORD_WEBHOOK_URL not configured.")
        return False

    payload = json.dumps({"content": content}).encode("utf-8")
    user_agent = f"dar-backup/{about.__version__}"

    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": user_agent,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds):
            pass
        log and log.debug(f"Discord webhook message sent using {source}.")
        return True
    except urllib.error.HTTPError as exc:
        # Attempt to read a short error body for diagnostics
        body = None
        try:
            body = exc.read().decode(errors="replace")
        except Exception:
            body = None
        detail = f" body='{body.strip()}'" if body else ""
        message = f"Discord webhook HTTP error {exc.code}: {exc.reason}{detail}"
        if log:
            log.error(message)
        else:
            print(message, file=sys.stderr)
    except Exception as exc:
        message = f"Failed to send Discord webhook message: {exc}"
        if log:
            log.error(message)
        else:
            print(message, file=sys.stderr)

    return False


def extract_version(output):
    match = re.search(r'(\d+\.\d+(\.\d+)?)', output)
    return match.group(1) if match else "unknown"


def get_binary_info(command):
    """
    Return information about a binary command.
    Args:
        command (str): The command to check.
    Returns:
        dict: A dictionary containing the command, path, version, and full output.
        Dict structure:
            {
                "command": str,
                "path": str,
                "version": str,
                "full_output": str
            }
    Raises:
        Exception: If there is an error running the command.
    """
    path = shutil.which(command)
    if path is None:
        return {
            "command": command,
            "path": "Not found",
            "version": "unknown",
            "full_output": ""
        }

    try:
        result = subprocess.run(
            [path, '--version'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        # Combine output regardless of return code
        combined_output = (result.stdout + result.stderr).strip()

        # Even if returncode != 0, the version info may still be valid
        version = extract_version(combined_output)

        return {
            "command": command,
            "path": path,
            "version": version if version else "unknown",
            "full_output": combined_output
        }

    except Exception as e:
        return {
            "command": command,
            "path": path,
            "version": "error",
            "full_output": str(e)
        }


def requirements(
    type: str,
    config_setting: ConfigSettings,
    report_out: typing.Optional[dict] = None,
) -> None:
    """
    Perform PREREQ or POSTREQ requirements.

    Args:
        type (str): The type of prereq (PREREQ, POSTREQ).
        config_setting (ConfigSettings): An instance of the ConfigSettings class.
        report_out (dict, optional): If provided, populated with execution results:
            ``{"status": "none"|"success"|"failure", "failures": [{"script": key, "message": str}]}``.
            Status starts as "none" (caller must initialise the dict before passing it in).
            Still raises on failure so callers can short-circuit if needed.

    Raises:
        RuntimeError: If a subprocess returns anything but zero.
        subprocess.CalledProcessError: if CalledProcessError is raised in subprocess.run(), let it bubble up.
    """

    if type is None or config_setting is None:
        raise RuntimeError("requirements: 'type' or config_setting is None")

    allowed_types = ['PREREQ', 'POSTREQ']
    if type not in allowed_types:
        raise RuntimeError(f"requirements: {type} not in: {allowed_types}")

    # -1 means no timeout (same convention as COMMAND_TIMEOUT_SECS elsewhere)
    timeout_secs = getattr(config_setting, 'command_timeout_secs', 30)
    timeout = None if timeout_secs == -1 else timeout_secs

    logger.debug(f"Performing  {type}")
    if type in config_setting.config:
        for key in sorted(config_setting.config[type].keys()):
            script = config_setting.config[type][key]
            try:
                # shell=True is intentional: PREREQ/POSTREQ scripts are arbitrary shell
                # expressions from a trusted config file and may use pipes, redirects,
                # or compound commands that require a shell to interpret.
                process = subprocess.Popen(
                    script,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    shell=True
                )
                stdout_lines = []
                stderr_lines = []

                def read_stream(stream, lines, level):
                    if stream is None:
                        return
                    for line in stream:
                        logger.log(level, line.rstrip())
                        lines.append(line)

                stdout_thread = threading.Thread(
                    target=read_stream,
                    args=(process.stdout, stdout_lines, logging.DEBUG)
                )
                stderr_thread = threading.Thread(
                    target=read_stream,
                    args=(process.stderr, stderr_lines, logging.ERROR)
                )
                stdout_thread.start()
                stderr_thread.start()

                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout_thread.join()
                    stderr_thread.join()
                    raise RuntimeError(
                        f"{type} {key}: '{script}' timed out after {timeout_secs}s"
                    )

                stdout_thread.join()
                stderr_thread.join()

                logger.debug(f"{type} {key}: '{script}' run, return code: {process.returncode}")
                if process.returncode != 0:
                    stderr_text = "".join(stderr_lines)
                    if stderr_text:
                        logger.error(f"{type} stderr:\n{stderr_text}")
                    raise RuntimeError(f"{type} {key}: '{script}' failed, return code: {process.returncode}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error executing {key}: '{script}': {e}")
                if report_out is not None:
                    report_out["status"] = "failure"
                    report_out["failures"].append({"script": key, "message": str(e)})
                raise
            except RuntimeError as e:
                if report_out is not None:
                    report_out["status"] = "failure"
                    report_out["failures"].append({"script": key, "message": str(e)})
                raise

        if report_out is not None:
            report_out["status"] = "success"




class BackupError(Exception):
    """Exception raised for errors in the backup process."""
    def __init__(self, msg="", dar_exit_code=None):
        super().__init__(msg)
        self.dar_exit_code = dar_exit_code

class DifferentialBackupError(BackupError):
    """Exception raised for errors in the differential backup process."""
    pass

class IncrementalBackupError(BackupError):
    """Exception raised for errors in the incremental backup process."""
    pass

class RestoreError(Exception):
    """Exception raised for errors in the restore process."""
    pass



def list_backups(backup_dir, backup_definition=None):
    """
    Lists the available backup files in the specified directory along with their total sizes in megabytes. 
    The function filters and processes `.dar` files, grouping them by their base names and ensuring proper 
    alignment of the displayed sizes.
    Args:
        backup_dir (str): The directory containing the backup files.
        backup_definition (str, optional): A prefix to filter backups by their base name. Only backups 
                                           starting with this prefix will be included. Defaults to None.
    Behavior:
        - Filters `.dar` files in the specified directory based on the following criteria:
            - The file name must contain one of the substrings: "_FULL_", "_DIFF_", or "_INCR_".
            - The file name must include a date in the format "_YYYY-MM-DD".
        - Groups files by their base name (excluding slice numbers and extensions) and calculates 
          the total size for each group in megabytes.
        - Sorts the backups by their base name and date (if included in the name).
        - Prints the backup names and their sizes in a formatted and aligned manner.
    Returns:
        None: The function prints the results directly to the console. If no backups are found, 
              it prints "No backups available.".

    List the available backups in the specified directory and their sizes in megabytes, with aligned sizes.
    """
    # Create a dictionary to hold backup names and their total sizes
    backup_sizes = {}

   # Define the date pattern
    date_pattern = re.compile(r'_\d{4}-\d{2}-\d{2}')
  

    # List all files and filter .dar files
    for f in os.listdir(backup_dir):
        if f.endswith('.dar'):
            # Extract the base name of the backup (without slice number and extension)
            base_name = f.rsplit('.', 2)[0]
            if backup_definition and not base_name.startswith(backup_definition):
                continue

            # Check if the base name contains any of the substrings
            substrings = ["_FULL_", "_DIFF_", "_INCR_"]
            if not any(substring in base_name for substring in substrings):
                continue

            # Check if the base name contains a date in the form "-YYYY-MM-DD"
            if not date_pattern.search(base_name):
                continue


            # Calculate the file size in megabytes
            file_path = os.path.join(backup_dir, f)
            try:
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            except OSError as e:
                get_logger().warning("Skipping %s: could not read file size: %s", file_path, e)
                continue
            
            # Accumulate the size for each base backup name
            if base_name in backup_sizes:
                backup_sizes[base_name] += file_size_mb
            else:
                backup_sizes[base_name] = file_size_mb
    
    if not backup_sizes:
        print("No backups available.")
        return
    
    # Determine the maximum length of the archive names
    max_name_length = max(len(name) for name in backup_sizes.keys())

    formatted_sizes = [f"{int(size):,}" for size in backup_sizes.values()]
    max_size_length = max(len(size) for size in formatted_sizes)

    def _sort_key(item: tuple) -> tuple:
        """Return (prefix, date) sort key; fall back to datetime.min for unparseable dates."""
        name = item[0]
        parts = name.split('_')
        prefix = parts[0]
        try:
            date = datetime.strptime(parts[-1], '%Y-%m-%d')
        except ValueError:
            date = datetime.min
        return (prefix, date)

    # Sort backups by name and possibly by date if included in the name
    sorted_backups = sorted(backup_sizes.items(), key=_sort_key)
    
    # Print the backups and their sizes with aligned sizes
    for backup, size in sorted_backups:
        formatted_size = f"{int(size):,}"
        print(f"{backup.ljust(max_name_length)} : {formatted_size.rjust(max_size_length)} MB")


def expand_path(path: str) -> str:
    """
    Expand ~ and environment variables like $HOME in a path.
    """
    return os.path.expanduser(os.path.expandvars(path))


def backup_definition_completer(prefix, parsed_args, **kwargs):
    try:
        config_file = get_config_file(parsed_args)
        config = ConfigSettings(config_file)
        backup_d_dir = os.path.expanduser(config.backup_d_dir)
        return [f for f in os.listdir(backup_d_dir) if f.startswith(prefix)]
    except Exception:
        completer_logger.exception("backup_definition_completer failed")
        return []


def extract_backup_definition_fallback() -> str:
    """
    Extracts --backup-definition or -d value directly from COMP_LINE.
    This is needed because argcomplete doesn't always populate parsed_args fully.

    Returns:
        str: The value of the --backup-definition argument if found, else an empty string.
    """
    comp_line = os.environ.get("COMP_LINE", "")
    try:
        tokens = shlex.split(comp_line)
    except ValueError:
        tokens = comp_line.split()

    for i, token in enumerate(tokens):
        if token in ("-d", "--backup-definition", "--backup-def"):
            if i + 1 < len(tokens):
                return tokens[i + 1]
        elif token.startswith(("--backup-definition=", "--backup-def=", "-d=")):
            return token.split("=", 1)[1]
    return ""




def list_archive_completer(prefix, parsed_args, **kwargs):
    try:
        import os
        import configparser
        from dar_backup.util import extract_backup_definition_fallback

        comp_line = os.environ.get("COMP_LINE", "")
        if "cleanup" in comp_line and "--cleanup-specific-archives" not in comp_line:
            return []

        backup_def = (
            getattr(parsed_args, "backup_definition", None)
            or getattr(parsed_args, "backup_def", None)
            or extract_backup_definition_fallback()
        )
        head, last = split_archive_list_prefix(prefix)
        config_path = get_config_file(parsed_args)
        if not os.path.exists(config_path):
            return []

        config = configparser.ConfigParser()
        config.read(config_path)
        backup_dir = config.get("DIRECTORIES", "BACKUP_DIR", fallback="")
        backup_dir = os.path.expanduser(os.path.expandvars(backup_dir))

        if not os.path.isdir(backup_dir):
            return []

        files = os.listdir(backup_dir)
        archive_re = re.compile(rf"^{re.escape(backup_def)}_.+_\d{{4}}-\d{{2}}-\d{{2}}\.1\.dar$") if backup_def else re.compile(r".+_\d{4}-\d{2}-\d{2}\.1\.dar$")

        completions = []
        for fname in files:
            if not archive_re.match(fname):
                continue
            base = fname.rsplit(".1.dar", 1)[0]
            if last and not base.startswith(last):
                continue
            if head:
                completions.append(f"{head}, {base}")
            else:
                completions.append(base)

        completions = sorted(set(completions), key=sort_key)
        return completions or ["[no matching archives]"]
    except Exception:
        completer_logger.exception("list_archive_completer failed")
        return []


def split_archive_list_prefix(prefix: str) -> tuple[str, str]:
    """
    Split a comma-separated archive list into (head, last).
    Strips whitespace so completions don't include leading/trailing spaces.
    """
    if not prefix or "," not in prefix:
        return ("", prefix.strip())
    parts = [part.strip() for part in prefix.split(",")]
    head_parts = [part for part in parts[:-1] if part]
    head = ", ".join(head_parts)
    last = parts[-1]
    return (head, last)



def sort_key(archive_name: str):
    """
    Sort by backup definition and then by date extracted from the archive name.
    Handles formats like: <def>_<TYPE>_<YYYY-MM-DD>.<N>.dar
    """
    try:
        base = archive_name.split('.')[0]  # remove .1.dar
        parts = base.split('_')
        if len(parts) < 3:
            return (archive_name, datetime.min)  # fallback for non-matching formats

        # Correct assumption: last two parts are TYPE and DATE
        def_name = '_'.join(parts[:-2])  # everything before _TYPE_DATE
        date_str = parts[-1]
        date = datetime.strptime(date_str, "%Y-%m-%d")
        completer_logger.debug(f"Archive: {archive_name}, Def: {def_name}, Date: {date}")
        return (def_name, date)
    except Exception:
        completer_logger.exception("sort_key failed")
        return (archive_name, datetime.min)




def archive_content_completer(prefix, parsed_args, **kwargs):
    """
    Completes archive names from all available *.db files.
    If --backup-def is given, only that one is used.
    Only entries found in the catalog database (via `dar_manager --list`) are shown.
    """

    try:
        from dar_backup.config_settings import ConfigSettings
        import subprocess
        import os

        # Expand config path
        config_file = get_config_file(parsed_args)
        config = ConfigSettings(config_file=config_file)
        #db_dir = expand_path((getattr(config, 'manager_db_dir', config.backup_dir)))   # use manager_db_dir if set, else backup_dir
        db_dir = expand_path(getattr(config, 'manager_db_dir', None) or config.backup_dir)

        # Which db files to inspect?
        backup_def = getattr(parsed_args, "backup_def", None)
        db_files = (
            [os.path.join( db_dir, f"{backup_def}.db")]
            if backup_def
            else [os.path.join( db_dir, f) for f in os.listdir( db_dir) if f.endswith(".db")]
        )

        completions = []

        for db_path in db_files:
            if not os.path.exists(db_path):
                continue

            try:
                result = subprocess.run(
                    ["dar_manager", "--base", db_path, "--list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=True,
                    timeout=10
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue

            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) >= 3:
                    archive = parts[2].strip()
                    if archive.startswith(prefix):
                        completions.append(archive)

        completions = sorted(set(completions), key=sort_key)
        return completions or ["[no matching archives]"]
    except Exception:
        completer_logger.exception("archive_content_completer failed")
        return []



def add_specific_archive_completer(prefix, parsed_args, **kwargs):
    """
    Autocompletes archives that are present in the BACKUP_DIR
    but not yet present in the <backup_def>.db catalog.
    If --backup-def is provided, restrict suggestions to that.
    """
    try:
        from dar_backup.config_settings import ConfigSettings
        import subprocess
        import re
        import os

        config_file = get_config_file(parsed_args)
        config = ConfigSettings(config_file=config_file)
        #db_dir = expand_path((getattr(config, 'manager_db_dir', config.backup_dir)))   # use manager_db_dir if set, else backup_dir
        db_dir = expand_path(getattr(config, 'manager_db_dir') or config.backup_dir)
        backup_dir = config.backup_dir
        backup_def = getattr(parsed_args, "backup_def", None)

        # Match pattern for archive base names: e.g. test_FULL_2025-04-01
        dar_pattern = re.compile(r"^(.*?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2}))\.1\.dar$")

        # Step 1: scan backup_dir for .1.dar files
        all_archives = set()
        for fname in os.listdir(backup_dir):
            match = dar_pattern.match(fname)
            if match:
                base = match.group(1)
                if base.startswith(prefix):
                    if not backup_def or base.startswith(f"{backup_def}_"):
                        all_archives.add(base)

        # Step 2: exclude ones already present in the .db
        db_path = os.path.join(db_dir, f"{backup_def}.db") if backup_def else None
        existing = set()

        if db_path and os.path.exists(db_path):
            try:
                result = subprocess.run(
                    ["dar_manager", "--base", db_path, "--list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    check=True,
                    timeout=10
                )
                for line in result.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 3:
                        existing.add(parts[2].strip())
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass

        # Step 3: return filtered list
        candidates = sorted(archive for archive in all_archives if archive not in existing)
        return candidates or ["[no new archives]"]
    except Exception:
        completer_logger.exception("add_specific_archive_completer failed")
        return []




def patch_config_file(path: str, replacements: dict) -> None:
    """
    Replace specific key values in a config file atomically.

    Writes to a temporary file in the same directory, then uses os.replace()
    to swap it in — the original is never partially overwritten if the process
    is interrupted mid-write.

    Args:
        path: Path to the config file.
        replacements: Dictionary of keys to new values, e.g., {"LOGFILE_LOCATION": "/tmp/logfile.log"}.
    """
    with open(path, 'r') as f:
        lines = f.readlines()

    dir_name = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=dir_name)
    replaced = False
    try:
        with os.fdopen(fd, 'w') as f:
            for line in lines:
                key = line.split('=')[0].strip()
                if key in replacements:
                    f.write(f"{key} = {replacements[key]}\n")
                else:
                    f.write(line)
        os.replace(tmp_path, path)
        replaced = True
    finally:
        if not replaced:
            os.unlink(tmp_path)




console = Console()

def print_aligned_settings(
    settings: List[Tuple[str, str]],
    log: bool = True,
    header: str = "Startup Settings",
    quiet: bool = True,
    highlight_keywords: List[str] = None
) -> None:
    """
    Print and optionally log settings nicely, using rich for color.
    Highlights settings if dangerous keywords are found inside label or text,
    but only if text is not None or empty.
    """
    if not settings:
        return

    settings = [(str(label), "" if text is None else str(text)) for label, text in settings]
    logger = get_logger()

    max_label_length = max(len(label) for label, _ in settings)

    header_line = f"========== {header} =========="
    footer_line = "=" * len(header_line)

    not quiet and console.print(f"[bold cyan]{header_line}[/bold cyan]")
    if log and logger:
        logger.info(header_line)

    for label, text in settings:
        padded_label = f"{label:<{max_label_length}}"

        label_clean = label.rstrip(":").lower()
        text_clean = text.lower()

        # Skip highlighting if text is empty
        if not text_clean.strip():
            danger = False
        else:
            danger = False
            if highlight_keywords:
                combined_text = f"{label_clean} {text_clean}"
                danger = any(keyword.lower() in combined_text for keyword in highlight_keywords)

        # Build the line
        line_text = Text()
        line_text.append(padded_label, style="bold")
        line_text.append(" ", style="none")

        if danger:
            line_text.append("[!]", style="bold red")
            line_text.append(" ", style="none")

        line_text.append(text, style="white")

        not quiet and console.print(line_text)

        # Always log clean text (no [!] in log)
        final_line_for_log = f"{padded_label} {text}"
        if log and logger:
            logger.info(final_line_for_log)

    not quiet and console.print(f"[bold cyan]{footer_line}[/bold cyan]")
    if log and logger:
        logger.info(footer_line)




def compare_metadata(source: str, restored: str) -> list[str]:
    """
    Compare file metadata between a source file and its restored counterpart.

    Checks permissions (st_mode) and modification time (st_mtime_ns).
    uid/gid are intentionally not checked: the darrc ships with
    --comparison-field=ignore-owner in the restore-options section so that
    non-root users can restore without permission errors.  As a result dar
    never restores ownership, making uid/gid comparison meaningless.

    Args:
        source: Absolute path to the original source file.
        restored: Absolute path to the restored file.

    Returns:
        List of human-readable mismatch descriptions.  Empty list means all
        checked attributes match.

    Raises:
        OSError: If either path cannot be stat'd.
    """
    mismatches: list[str] = []
    src = os.stat(source)
    rst = os.stat(restored)

    if src.st_mode != rst.st_mode:
        mismatches.append(
            f"permission mismatch: source={oct(src.st_mode)} restored={oct(rst.st_mode)}"
        )

    if src.st_mtime_ns != rst.st_mtime_ns:
        mismatches.append(
            f"mtime mismatch: source={src.st_mtime_ns} restored={rst.st_mtime_ns}"
        )

    return mismatches


def normalize_dir(path: str) -> str:
    """
    Strip any trailing slash/backslash but leave root ("/" or "C:\\") intact.
    """
    p = Path(path)
    # Path(__str__) drops any trailing separators
    normalized = str(p)
    return normalized



# Reusable pattern for archive file naming
archive_pattern = re.compile(
    r'^.+?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2})'
    r'(?:'
    r'\.\d+\.dar(?:\.vol\d+(?:\+\d+)?\.par2|\.par2)?'
    r'|(?:\.vol\d+(?:\+\d+)?\.par2|\.par2)'
    r'|\.par2\.manifest\.ini'
    r')$'
)

def is_safe_filename(filename: str) -> bool:
    """
    Validates that the filename matches acceptable dar/par2 naming convention.
    """
    return archive_pattern.match(filename) is not None

def is_safe_path(path: str) -> bool:
    """
    Validates that the full path is absolute, has no '..'.
    """
    normalized = os.path.normpath(path)
    filename = os.path.basename(normalized)

    return (
        os.path.isabs(normalized)
        and '..' not in normalized.split(os.sep)
    )

def get_config_file(args) -> str:
    """
    Returns the config file path based on the following precedence:
    1. Command-line argument (--config-file)
    2. Environment variable (DAR_BACKUP_CONFIG_FILE)
    3. Default path (~/.config/dar-backup/dar-backup.conf)
    """
    DEFAULT_CONFIG_FILE = "~/.config/dar-backup/dar-backup.conf"

    env_cf = os.getenv("DAR_BACKUP_CONFIG_FILE")
    env_cf = env_cf.strip() if env_cf else None

    cli_cf = getattr(args, "config_file", None)
    cli_cf = cli_cf.strip() if cli_cf else None
    
    raw_config = (
        cli_cf
        or env_cf
        or DEFAULT_CONFIG_FILE
    )

    config_settings_path = os.path.abspath(os.path.expanduser(os.path.expandvars(raw_config)))
    return config_settings_path



def is_under_base_dir(candidate: Path, base_dir: Path) -> bool:
    """
    True iff candidate resolves under base_dir (symlink-safe).
    """
    try:
        base = base_dir.resolve(strict=True)
        resolved = candidate.resolve(strict=False)
    except Exception:
        return False
    return resolved == base or base in resolved.parents


def safe_remove_file(path_str: str, *, base_dir: Path) -> bool:
    """
    Remove a file only if it:
      - is under base_dir (after resolve),
      - matches archive naming convention by BASENAME,
      - is a regular file (not a dir),
      - is not a symlink (optional hardening).
    Returns True if removed.
    """
    p = Path(path_str)

    # Enforce containment first (defeats ../ and symlink escape)
    if not is_under_base_dir(p, base_dir):
        logger.warning("Refusing to delete outside base_dir: %s (base=%s)", p, base_dir)
        return False

    # Validate filename shape on basename only
    if not is_safe_filename(p.name):
        logger.warning("Refusing to delete non-matching filename: %s", p.name)
        return False

    # Hardening: don't follow symlinks
    if p.is_symlink():
        logger.warning("Refusing to delete symlink: %s", p)
        return False

    # Only delete regular files
    if not p.is_file():
        logger.warning("Refusing to delete non-file: %s", p)
        return False

    p.unlink()
    return True



# Allowed archive name:
#   <definition>_(FULL|DIFF|INCR)_YYYY-MM-DD
# Example:
#   pj-homedir_INCR_2025-11-22
_ARCHIVE_NAME_RE = re.compile(
    r"^(?P<def>[A-Za-z0-9][A-Za-z0-9._-]{0,127})_"
    r"(?P<kind>FULL|DIFF|INCR)_"
    r"(?P<date>\d{4}-\d{2}-\d{2})$"
)

_METRICS_DDL = """
CREATE TABLE IF NOT EXISTS backup_runs (
    id                            INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_definition             TEXT    NOT NULL,
    backup_type                   TEXT    NOT NULL CHECK (backup_type IN ('FULL', 'DIFF', 'INCR')),
    archive_name                  TEXT,
    dar_backup_version            TEXT,
    dar_version                   TEXT,
    run_started_at                TEXT    NOT NULL,
    run_finished_at               TEXT,
    duration_secs                 REAL,
    dar_duration_secs             REAL,
    verify_duration_secs          REAL,
    par2_duration_secs            REAL,
    status                        TEXT    NOT NULL CHECK (status IN ('SUCCESS', 'WARNING', 'FAILURE')),
    dar_exit_code                 INTEGER,
    failed_phase                  TEXT    CHECK (failed_phase IS NULL OR failed_phase IN ('PREREQ', 'DAR', 'VERIFY', 'PAR2')),
    error_summary                 TEXT,
    catalog_updated               INTEGER,
    verify_passed                 INTEGER,
    restore_test_passed           INTEGER,
    par2_passed                   INTEGER,
    archive_size_bytes            INTEGER,
    num_slices                    INTEGER,
    par2_size_bytes               INTEGER,
    files_verified                INTEGER,
    backup_dir_free_bytes         INTEGER,
    hostname                      TEXT,
    run_id                        TEXT,
    prereq_status                 TEXT    CHECK (prereq_status  IS NULL OR prereq_status  IN ('SUCCESS', 'FAILURE')),
    postreq_status                TEXT    CHECK (postreq_status IS NULL OR postreq_status IN ('SUCCESS', 'FAILURE')),
    inodes_saved                  INTEGER,
    hard_links_treated            INTEGER,
    inodes_changed_during_backup  INTEGER,
    bytes_wasted                  INTEGER,
    inodes_metadata_only          INTEGER,
    inodes_not_saved              INTEGER,
    inodes_failed                 INTEGER,
    inodes_excluded               INTEGER,
    inodes_deleted                INTEGER,
    inodes_total                  INTEGER,
    ea_saved                      INTEGER,
    fsa_saved                     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_runs_definition
    ON backup_runs (backup_definition, backup_type, run_started_at);
CREATE INDEX IF NOT EXISTS idx_runs_status
    ON backup_runs (status, run_started_at);
CREATE INDEX IF NOT EXISTS idx_runs_dar_exit_code
    ON backup_runs (dar_exit_code, run_started_at);

CREATE TABLE IF NOT EXISTS restore_test_fail_reasons (
    id    INTEGER PRIMARY KEY,
    code  TEXT    NOT NULL UNIQUE
);
INSERT OR IGNORE INTO restore_test_fail_reasons (id, code) VALUES
    (1, 'CONTENT_MISMATCH'),
    (2, 'METADATA_MISMATCH'),
    (3, 'SOURCE_MISSING'),
    (4, 'RESTORED_MISSING'),
    (5, 'PERMISSION_ERROR'),
    (6, 'UNKNOWN_ERROR');

CREATE TABLE IF NOT EXISTS restore_test_samples (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            TEXT    NOT NULL,
    backup_definition TEXT    NOT NULL,
    archive_name      TEXT    NOT NULL,
    file_path         TEXT    NOT NULL,
    file_size_bytes   INTEGER,
    result            TEXT    NOT NULL CHECK (result IN ('PASS', 'FAIL', 'SKIP')),
    fail_reason_id    INTEGER REFERENCES restore_test_fail_reasons(id),
    fail_detail       TEXT,
    tested_at         TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_run_id
    ON restore_test_samples (run_id);
"""


# Each entry: (metric_key, compiled_regex).  The regex must have exactly one
# capture group that matches the integer value.  If dar changes its output
# format the pattern simply won't match and the value is stored as NULL —
# the backup run is never affected.
_DAR_STAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("inodes_saved",                 re.compile(r'(\d+)\s+inode\(s\)\s+saved')),
    ("hard_links_treated",           re.compile(r'including\s+(\d+)\s+hard\s+link\(s\)\s+treated')),
    ("inodes_changed_during_backup", re.compile(r'(\d+)\s+inode\(s\)\s+changed\s+at\s+the\s+moment\s+of\s+the\s+backup')),
    ("bytes_wasted",                 re.compile(r'(\d+)\s+byte\(s\)\s+have\s+been\s+wasted')),
    ("inodes_metadata_only",         re.compile(r'(\d+)\s+inode\(s\)\s+with\s+only\s+metadata\s+changed')),
    ("inodes_not_saved",             re.compile(r'(\d+)\s+inode\(s\)\s+not\s+saved\s+\(no\s+inode/file\s+change\)')),
    ("inodes_failed",                re.compile(r'(\d+)\s+inode\(s\)\s+failed\s+to\s+be\s+saved')),
    ("inodes_excluded",              re.compile(r'(\d+)\s+inode\(s\)\s+ignored\s+\(excluded\s+by\s+filters\)')),
    ("inodes_deleted",               re.compile(r'(\d+)\s+inode\(s\)\s+recorded\s+as\s+deleted')),
    ("inodes_total",                 re.compile(r'Total\s+number\s+of\s+inode\(s\)\s+considered:\s*(\d+)')),
    ("ea_saved",                     re.compile(r'EA\s+saved\s+for\s+(\d+)\s+inode\(s\)')),
    ("fsa_saved",                    re.compile(r'FSA\s+saved\s+for\s+(\d+)\s+inode\(s\)')),
]


def parse_dar_stats(output: str) -> dict[str, typing.Optional[int]]:
    """
    Parse dar's inode summary block from captured command output.

    Each metric is extracted via a dedicated regex.  If a pattern does not
    match (e.g. because dar changed its output format, or the run failed
    before the summary was printed) the corresponding value is ``None`` so
    that a NULL is stored in the metrics DB rather than crashing.

    Args:
        output: The full stdout string captured from a dar invocation.

    Returns:
        A dict mapping each inode stat key to an ``int`` or ``None``.
    """
    if not output:
        return {key: None for key, _ in _DAR_STAT_PATTERNS}

    result: dict[str, typing.Optional[int]] = {}
    for key, pattern in _DAR_STAT_PATTERNS:
        m = pattern.search(output)
        if m:
            try:
                result[key] = int(m.group(1))
            except (ValueError, IndexError):
                result[key] = None
        else:
            result[key] = None
    return result


# Columns added after the initial schema release, in order of introduction.
# Each entry: (column_name, SQLite type declaration).
# ensure_metrics_db() issues ALTER TABLE ADD COLUMN IF NOT EXISTS for each,
# so existing databases are migrated automatically and silently.
_METRICS_MIGRATIONS: list[tuple[str, str]] = [
    ("hostname",                      "TEXT"),
    ("inodes_saved",                  "INTEGER"),
    ("hard_links_treated",            "INTEGER"),
    ("inodes_changed_during_backup",  "INTEGER"),
    ("bytes_wasted",                  "INTEGER"),
    ("inodes_metadata_only",          "INTEGER"),
    ("inodes_not_saved",              "INTEGER"),
    ("inodes_failed",                 "INTEGER"),
    ("inodes_excluded",               "INTEGER"),
    ("inodes_deleted",                "INTEGER"),
    ("inodes_total",                  "INTEGER"),
    ("ea_saved",                      "INTEGER"),
    ("fsa_saved",                     "INTEGER"),
    ("run_id",                        "TEXT"),
    ("prereq_status",                 "TEXT"),
    ("postreq_status",                "TEXT"),
]


# Stable IDs matching the seeds in restore_test_fail_reasons.
RESTORE_FAIL_CONTENT_MISMATCH: int = 1
RESTORE_FAIL_METADATA_MISMATCH: int = 2
RESTORE_FAIL_SOURCE_MISSING: int = 3
RESTORE_FAIL_RESTORED_MISSING: int = 4
RESTORE_FAIL_PERMISSION_ERROR: int = 5
RESTORE_FAIL_UNKNOWN_ERROR: int = 6


def ensure_metrics_db(db_path: str) -> None:
    """Create the metrics DB schema if it does not already exist, and migrate older DBs.

    Safe to call on every backup run:
      - New DB: full schema is created by _METRICS_DDL.
      - Existing DB: ALTER TABLE ADD COLUMN IF NOT EXISTS is issued for every
        column listed in _METRICS_MIGRATIONS, so columns added after the
        initial release are silently appended without touching existing data.
    """
    with closing(sqlite3.connect(db_path)) as conn:
        # WAL mode lets Datasette/sqlite3-CLI read without blocking backup writes.
        # Stored in the DB file — only needs to be set once.
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_METRICS_DDL)
        existing = {row[1] for row in conn.execute("PRAGMA table_info(backup_runs)")}
        for col_name, col_type in _METRICS_MIGRATIONS:
            if col_name not in existing:
                conn.execute(
                    f"ALTER TABLE backup_runs ADD COLUMN {col_name} {col_type}"
                )


def write_metrics_row(metrics: dict, config_settings) -> None:
    """Write one metrics row to the SQLite metrics DB.

    Errors are caught and logged — metrics must never abort a backup run.
    If config_settings.metrics_db_path is None or empty, this is a silent no-op.
    """
    db_path = getattr(config_settings, "metrics_db_path", None)
    if not db_path:
        return
    try:
        db_path = os.path.expanduser(os.path.expandvars(db_path))
        ensure_metrics_db(db_path)
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute(
                """
                INSERT INTO backup_runs (
                    backup_definition, backup_type, archive_name,
                    dar_backup_version, dar_version,
                    run_started_at, run_finished_at, duration_secs,
                    dar_duration_secs, verify_duration_secs, par2_duration_secs,
                    status, dar_exit_code, failed_phase, error_summary,
                    catalog_updated, verify_passed, restore_test_passed, par2_passed,
                    archive_size_bytes, num_slices, par2_size_bytes,
                    files_verified, backup_dir_free_bytes,
                    hostname,
                    inodes_saved, hard_links_treated, inodes_changed_during_backup,
                    bytes_wasted, inodes_metadata_only, inodes_not_saved,
                    inodes_failed, inodes_excluded, inodes_deleted,
                    inodes_total, ea_saved, fsa_saved,
                    run_id, prereq_status, postreq_status
                ) VALUES (
                    :backup_definition, :backup_type, :archive_name,
                    :dar_backup_version, :dar_version,
                    :run_started_at, :run_finished_at, :duration_secs,
                    :dar_duration_secs, :verify_duration_secs, :par2_duration_secs,
                    :status, :dar_exit_code, :failed_phase, :error_summary,
                    :catalog_updated, :verify_passed, :restore_test_passed, :par2_passed,
                    :archive_size_bytes, :num_slices, :par2_size_bytes,
                    :files_verified, :backup_dir_free_bytes,
                    :hostname,
                    :inodes_saved, :hard_links_treated, :inodes_changed_during_backup,
                    :bytes_wasted, :inodes_metadata_only, :inodes_not_saved,
                    :inodes_failed, :inodes_excluded, :inodes_deleted,
                    :inodes_total, :ea_saved, :fsa_saved,
                    :run_id, :prereq_status, :postreq_status
                )
                """,
                metrics,
            )
            conn.commit()
    except Exception as exc:
        log = get_logger()
        if log:
            log.warning("Failed to write metrics row: %s", exc)


def write_restore_test_samples(
    run_id: str,
    backup_definition: str,
    archive_name: str,
    samples: list[dict],
    config_settings,
) -> None:
    """Write per-file restore-test results to the metrics DB in one transaction.

    Errors are caught and logged — metrics must never abort a backup run.
    If config_settings.metrics_db_path is None/empty, or samples is empty,
    this is a silent no-op.

    Args:
        run_id: UUID shared with the backup_runs row for this invocation.
        backup_definition: Name of the backup definition (e.g. 'homedir').
        archive_name: Base name of the archive (e.g. 'homedir_FULL_2026-05-26').
        samples: List of dicts with keys: file_path, file_size_bytes, result,
                 fail_reason_id, fail_detail, tested_at.
        config_settings: Configuration object; metrics_db_path must be set.
    """
    db_path = getattr(config_settings, "metrics_db_path", None)
    if not db_path or not samples:
        return
    try:
        db_path = os.path.expanduser(os.path.expandvars(db_path))
        ensure_metrics_db(db_path)
        rows = [
            (
                run_id,
                backup_definition,
                archive_name,
                s["file_path"],
                s.get("file_size_bytes"),
                s["result"],
                s.get("fail_reason_id"),
                s.get("fail_detail"),
                s["tested_at"],
            )
            for s in samples
        ]
        with closing(sqlite3.connect(db_path)) as conn:
            conn.executemany(
                """
                INSERT INTO restore_test_samples
                    (run_id, backup_definition, archive_name, file_path,
                     file_size_bytes, result, fail_reason_id, fail_detail, tested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
    except Exception as exc:
        log = get_logger()
        if log:
            log.warning("Failed to write restore_test_samples: %s", exc)


def update_postreq_status(run_id: str, status: str, config_settings) -> None:
    """
    Set postreq_status for every backup_runs row that belongs to this run.

    Called after requirements('POSTREQ', …) resolves (success or failure) so
    that the Dashboard can show the POST phase result alongside each backup row.
    Errors are caught and logged — they must never abort the backup process.

    Args:
        run_id:          UUID generated at the start of main(); shared by all
                         rows written during the same invocation.
        status:          'SUCCESS' or 'FAILURE'.
        config_settings: Configuration object; metrics_db_path must be set or
                         this is a silent no-op.
    """
    db_path = getattr(config_settings, "metrics_db_path", None)
    if not db_path:
        return
    try:
        db_path = os.path.expanduser(os.path.expandvars(db_path))
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute(
                "UPDATE backup_runs SET postreq_status = ? WHERE run_id = ?",
                (status, run_id),
            )
            conn.commit()
    except Exception as exc:
        log = get_logger()
        if log:
            log.warning("Failed to update postreq_status: %s", exc)


def is_archive_name_allowed(name: str) -> bool:
    """
    Return True iff the archive name is safe and valid.

    Security properties:
      - name only, never a path (no /, \\, or ..)
      - strict allowed character set
      - must be FULL / DIFF / INCR
      - date must be a real calendar date
    """
    if not isinstance(name, str):
        return False

    name = name.strip()

    # Reject anything path-like
    if "/" in name or "\\" in name or ".." in name:
        return False

    m = _ARCHIVE_NAME_RE.match(name)
    if not m:
        return False

    # Validate date is real (not just shape)
    try:
        date.fromisoformat(m.group("date"))   # <-- FIX
        # alternatively:
        # datetime.strptime(m.group("date"), "%Y-%m-%d")
    except ValueError:
        return False

    return True
