# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import logging
import traceback
import threading
import os
import re
import shlex
import sys
from collections import deque
try:
    import termios
except ImportError:
    termios = None
import tempfile
import time
from typing import List, Optional, Union
from dar_backup.util import get_logger


def is_safe_arg(arg: str) -> bool:
    """
    Check if the argument is safe by rejecting dangerous shell characters.
    """
    return not re.search(r'[;&|><`$\n]', arg)


def sanitize_cmd(cmd: List[str]) -> List[str]:
    """
    Validate and sanitize a list of command-line arguments.
    Ensures all elements are strings and do not contain dangerous shell characters.
    Raises ValueError if any argument is unsafe.
    """

    if not isinstance(cmd, list):
        raise ValueError("Command must be a list of strings")
    for arg in cmd:
        if not isinstance(arg, str):
            raise ValueError(f"Invalid argument type: {arg} (must be string)")
        if not is_safe_arg(arg):
            raise ValueError(f"Unsafe argument detected: {arg}")
    return cmd

def _safe_str(s):
    if isinstance(s, bytes):
        return f"<{len(s)} bytes of binary data>"
    return s


class CommandResult:
    def __init__(
        self,
        returncode: int,
        stdout: Union[str, bytes],
        stderr: Union[str, bytes],
        stack: Optional[str] = None,
        note: Optional[str] = None,
        stdout_tail: str = "",
        stderr_tail: str = "",
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stack = stack
        self.note = note
        # Rolling tail of the last N lines, always populated even when stdout/stderr
        # is truncated by capture_output_limit_bytes.  Used to parse end-of-output
        # summaries (e.g. dar inode statistics) that would otherwise be lost.
        self.stdout_tail = stdout_tail
        self.stderr_tail = stderr_tail



    def __repr__(self):
        return f"<CommandResult returncode={self.returncode}\nstdout={self.stdout}\nstderr={self.stderr}\nstack={self.stack}>"


    def __str__(self):
        return (
            "CommandResult:\n"
            f"  Return code: {self.returncode}\n"
            f"  Note: {self.note if self.note else '<none>'}\n"
            f"  STDOUT: {_safe_str(self.stdout)}\n"
            f"  STDERR: {_safe_str(self.stderr)}\n"
            f"  Stacktrace: {self.stack if self.stack else '<none>'}"
        )


class CommandRunner:
    def __init__(
        self,
        logger: Optional[logging.Logger] = None,
        command_logger: Optional[logging.Logger] = None,
        default_timeout: int = 30,
        default_capture_limit_bytes: Optional[int] = None
    ):
        self.logger = logger or get_logger()
        self.command_logger = command_logger or get_logger(command_output_logger=True)
        if default_timeout is not None:
            try:
                default_timeout = int(default_timeout)
            except (TypeError, ValueError):
                default_timeout = 30
            if not isinstance(default_timeout, int):
                default_timeout = 30
        self.default_timeout = default_timeout
        self.default_capture_limit_bytes = default_capture_limit_bytes

        if not self.logger or not self.command_logger:
            self.logger_fallback()

        if self.default_timeout is not None and self.default_timeout <= 0:
            self.default_timeout = None

    def logger_fallback(self):
        """
        Setup temporary log files
        """
        main_log = tempfile.NamedTemporaryFile(delete=False)
        command_log = tempfile.NamedTemporaryFile(delete=False)

        logger = logging.getLogger("command_runner_fallback_main_logger")
        command_logger = logging.getLogger("command_runner_fallback_command_logger")
        logger.setLevel(logging.DEBUG)
        command_logger.setLevel(logging.DEBUG)

        main_handler = logging.FileHandler(main_log.name)
        command_handler = logging.FileHandler(command_log.name)

        logger.addHandler(main_handler)
        command_logger.addHandler(command_handler)

        self.logger = logger
        self.command_logger = command_logger
        self.default_timeout = 30
        self.logger.info("CommandRunner initialized with fallback loggers")
        self.command_logger.info("CommandRunner initialized with fallback loggers")

        print(f"[WARN] Using fallback loggers:\n  Main log: {main_log.name}\n  Command log: {command_log.name}", file=sys.stderr)



    def run(
        self,
        cmd: List[str],
        *,
        timeout: Optional[int] = None,
        check: bool = False,
        capture_output: bool = True,
        capture_output_limit_bytes: Optional[int] = None,
        log_output: bool = True,
        text: bool = True,
        cwd: Optional[str] = None,
        stdin: Optional[int] = subprocess.DEVNULL
    ) -> CommandResult:
        self._text_mode = text
        if timeout is None:
            timeout = self.default_timeout
        if timeout is not None and timeout <= 0:
            timeout = None
        if capture_output_limit_bytes is None:
            capture_output_limit_bytes = self.default_capture_limit_bytes
        if capture_output_limit_bytes is not None and capture_output_limit_bytes < 0:
            capture_output_limit_bytes = None

        tty_fd = None
        tty_file = None
        saved_tty_attrs = None
        if termios is not None:
            try:
                if os.path.exists("/dev/tty"):
                    tty_file = open("/dev/tty")
                    tty_fd = tty_file.fileno()
                elif sys.stdin and sys.stdin.isatty():
                    tty_fd = sys.stdin.fileno()
                if tty_fd is not None:
                    saved_tty_attrs = termios.tcgetattr(tty_fd)
            except Exception:
                tty_fd = None
                saved_tty_attrs = None
                if tty_file:
                    tty_file.close()
                    tty_file = None

        try:
            cmd_sanitized = None

            try:
                cmd_sanitized = sanitize_cmd(cmd)
            except ValueError as e:
                stack = traceback.format_exc()
                self.logger.error(f"Command sanitation failed: {e}")
                if isinstance(cmd, list):
                    cmd_text = " ".join(map(str, cmd))
                else:
                    cmd_text = str(cmd)
                return CommandResult(
                    returncode=-1,
                    note=f"Sanitizing failed: command: {cmd_text}",
                    stdout='',
                    stderr=str(e),
                    stack=stack,

                )
            finally:
                cmd = cmd_sanitized

            #command = f"Executing command: {' '.join(cmd)} (timeout={timeout}s)"
            command = f"Executing command: {' '.join(shlex.quote(arg) for arg in cmd)} (timeout={timeout}s)"


            self.command_logger.info(command)
            self.logger.debug(command)

            stdout_lines = []
            stderr_lines = []
            truncated_stdout = {"value": False}
            truncated_stderr = {"value": False}
            # Rolling tail buffers: always keep the last 500 lines regardless of
            # whether the main capture limit has been reached.
            _TAIL_LINES = 500
            stdout_tail_deque: deque = deque(maxlen=_TAIL_LINES)
            stderr_tail_deque: deque = deque(maxlen=_TAIL_LINES)

            try:
                start_time = time.monotonic()
                use_pipes = capture_output or log_output
                cmd_env = os.environ.copy()
                cmd_env["LC_ALL"] = "C"
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE if use_pipes else None,
                    stderr=subprocess.PIPE if use_pipes else None,
                    stdin=stdin,
                    text=False,
                    bufsize=-1,
                    cwd=cwd,
                    env=cmd_env,
                )
                pid = getattr(process, "pid", None)
                if log_output:
                    self.command_logger.debug(
                        "Process started pid=%s cwd=%s",
                        pid if pid is not None else "unknown",
                        cwd or os.getcwd(),
                    )
                self.logger.debug(
                    "Process started pid=%s cwd=%s",
                    pid if pid is not None else "unknown",
                    cwd or os.getcwd(),
                )
            except Exception as e:
                self.logger.error(
                    "Failed to start command: %s (error=%s)",
                    " ".join(shlex.quote(arg) for arg in cmd),
                    e,
                )
                stack = traceback.format_exc()
                return CommandResult(
                    returncode=-1,
                    stdout='',
                    stderr=str(e),
                    stack=stack
                )

            def stream_output(stream, lines, level, truncated_flag, tail_deque):
                """Read *stream* in 1 KiB chunks, log each chunk, append to *lines*
                up to *capture_output_limit_bytes*, and unconditionally append every
                decoded line to *tail_deque* (capped at maxlen=500).  The tail is
                used to recover end-of-output summaries (e.g. dar inode stats) that
                would otherwise be lost when the main capture limit is exceeded."""
                captured_bytes = 0
                try:
                    while True:
                        chunk = stream.read(1024)
                        if not chunk:
                            break
                        if self._text_mode:
                            decoded = chunk.decode('utf-8', errors='replace')
                            if log_output:
                                self.command_logger.log(level, decoded.strip())
                            # Always feed the tail buffer regardless of capture limit.
                            for line in decoded.splitlines():
                                tail_deque.append(line)
                            if capture_output:
                                if capture_output_limit_bytes is None:
                                    lines.append(decoded)
                                else:
                                    remaining = capture_output_limit_bytes - captured_bytes
                                    if remaining > 0:
                                        if len(chunk) <= remaining:
                                            lines.append(decoded)
                                            captured_bytes += len(chunk)
                                        else:
                                            piece = chunk[:remaining]
                                            lines.append(piece.decode('utf-8', errors='replace'))
                                            captured_bytes = capture_output_limit_bytes
                                            truncated_flag["value"] = True
                                    else:
                                        truncated_flag["value"] = True
                        else:
                            if capture_output:
                                if capture_output_limit_bytes is None:
                                    lines.append(chunk)
                                else:
                                    remaining = capture_output_limit_bytes - captured_bytes
                                    if remaining > 0:
                                        if len(chunk) <= remaining:
                                            lines.append(chunk)
                                            captured_bytes += len(chunk)
                                        else:
                                            lines.append(chunk[:remaining])
                                            captured_bytes = capture_output_limit_bytes
                                            truncated_flag["value"] = True
                                    else:
                                        truncated_flag["value"] = True
                            # Avoid logging raw binary data to prevent garbled logs
                except Exception as e:
                    self.logger.warning(f"stream_output decode error: {e}")
                finally:
                    stream.close()

            threads = []
            if (capture_output or log_output) and process.stdout:
                t_out = threading.Thread(
                    target=stream_output,
                    args=(process.stdout, stdout_lines, logging.INFO, truncated_stdout, stdout_tail_deque)
                )
                t_out.start()
                threads.append(t_out)
            if (capture_output or log_output) and process.stderr:
                t_err = threading.Thread(
                    target=stream_output,
                    args=(process.stderr, stderr_lines, logging.ERROR, truncated_stderr, stderr_tail_deque)
                )
                t_err.start()
                threads.append(t_err)

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                duration = time.monotonic() - start_time
                pid = getattr(process, "pid", None)
                log_msg = (
                    f"Command timed out after {timeout} seconds: {' '.join(cmd)} "
                    f"(pid={pid if pid is not None else 'unknown'}, elapsed={duration:.2f}s):\n"
                )
                self.logger.error(log_msg)
                return CommandResult(-1, ''.join(stdout_lines), log_msg.join(stderr_lines))
            except Exception as e:
                stack = traceback.format_exc()
                log_msg = f"Command execution failed: {' '.join(cmd)} with error: {e}\n"
                self.logger.error(log_msg)
                return CommandResult(-1, ''.join(stdout_lines), log_msg.join(stderr_lines), stack)

            for t in threads:
                t.join()
            duration = time.monotonic() - start_time
            pid = getattr(process, "pid", None)
            if log_output:
                self.command_logger.debug(
                    "Process finished pid=%s returncode=%s elapsed=%.2fs",
                    pid if pid is not None else "unknown",
                    process.returncode,
                    duration,
                )
            self.logger.debug(
                "Process finished pid=%s returncode=%s elapsed=%.2fs",
                pid if pid is not None else "unknown",
                process.returncode,
                duration,
            )
            if process.returncode != 0:
                self.logger.error(
                    "Command failed pid=%s returncode=%s: %s",
                    pid if pid is not None else "unknown",
                    process.returncode,
                    " ".join(shlex.quote(arg) for arg in cmd),
                )

            if self._text_mode:
                stdout_combined = ''.join(stdout_lines)
                stderr_combined = ''.join(stderr_lines)
            else:
                stdout_combined = b''.join(stdout_lines)
                stderr_combined = b''.join(stderr_lines)

            note = None
            if truncated_stdout["value"] or truncated_stderr["value"]:
                parts = []
                if truncated_stdout["value"]:
                    parts.append("stdout truncated")
                if truncated_stderr["value"]:
                    parts.append("stderr truncated")
                note = ", ".join(parts)

            stdout_tail = "\n".join(stdout_tail_deque)
            stderr_tail = "\n".join(stderr_tail_deque)

            if check and process.returncode != 0:
                self.logger.error(f"Command failed with exit code {process.returncode}")
                return CommandResult(
                    process.returncode,
                    stdout_combined,
                    stderr_combined,
                    stack=traceback.format_stack(),
                    stdout_tail=stdout_tail,
                    stderr_tail=stderr_tail,
                )

            return CommandResult(
                process.returncode,
                stdout_combined,
                stderr_combined,
                note=note,
                stdout_tail=stdout_tail,
                stderr_tail=stderr_tail,
            )
        finally:
            if termios is not None and saved_tty_attrs is not None and tty_fd is not None:
                try:
                    termios.tcsetattr(tty_fd, termios.TCSADRAIN, saved_tty_attrs)
                except Exception:
                    self.logger.debug("Failed to restore terminal attributes", exc_info=True)
            if tty_file is not None:
                try:
                    tty_file.close()
                except Exception:
                    self.logger.debug("Failed to close /dev/tty handle", exc_info=True)
