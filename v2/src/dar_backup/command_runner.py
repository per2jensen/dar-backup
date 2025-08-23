# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import logging
import traceback
import threading
import os
import re
import shlex
import sys
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
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
        note: Optional[str] = None
    ):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stack = stack
        self.note = note



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
        default_timeout: int = 30
    ):
        self.logger = logger or get_logger()
        self.command_logger = command_logger or get_logger(command_output_logger=True)
        self.default_timeout = default_timeout

        if not self.logger or not self.command_logger:
            self.logger_fallback()


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
        text: bool = True
    ) -> CommandResult:
        self._text_mode = text 
        timeout = timeout or self.default_timeout

        cmd_sanitized = None

        try:
            cmd_sanitized = sanitize_cmd(cmd)
        except ValueError as e:
            stack = traceback.format_exc()
            self.logger.error(f"Command sanitation failed: {e}")
            return CommandResult(
                returncode=-1,
                note=f"Sanitizing failed: command: {' '.join(cmd)}",
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

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                text=False,
                bufsize=-1
            )
        except Exception as e:
            stack = traceback.format_exc()
            return CommandResult(
                returncode=-1,
                stdout='',
                stderr=str(e),
                stack=stack
            )

        def stream_output(stream, lines, level):
            try:
                while True:
                    chunk = stream.read(1024)
                    if not chunk:
                        break
                    if self._text_mode:
                        decoded = chunk.decode('utf-8', errors='replace')
                        lines.append(decoded)
                        self.command_logger.log(level, decoded.strip())
                    else:
                        lines.append(chunk)
                        # Avoid logging raw binary data to prevent garbled logs
            except Exception as e:
                self.logger.warning(f"stream_output decode error: {e}")
            finally:
                stream.close()



        threads = []
        if capture_output and process.stdout:
            t_out = threading.Thread(target=stream_output, args=(process.stdout, stdout_lines, logging.INFO))
            t_out.start()
            threads.append(t_out)
        if capture_output and process.stderr:
            t_err = threading.Thread(target=stream_output, args=(process.stderr, stderr_lines, logging.ERROR))
            t_err.start()
            threads.append(t_err)

        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            log_msg = f"Command timed out after {timeout} seconds: {' '.join(cmd)}:\n"
            self.logger.error(log_msg)
            return CommandResult(-1, ''.join(stdout_lines), log_msg.join(stderr_lines))
        except Exception as e:
            stack = traceback.format_exc()
            log_msg = f"Command execution failed: {' '.join(cmd)} with error: {e}\n"
            self.logger.error(log_msg)
            return CommandResult(-1, ''.join(stdout_lines), log_msg.join(stderr_lines), stack)  

        for t in threads:
            t.join()



        if self._text_mode:
            stdout_combined = ''.join(stdout_lines)
            stderr_combined = ''.join(stderr_lines)
        else:
            stdout_combined = b''.join(stdout_lines)
            stderr_combined = b''.join(stderr_lines)


        if check and process.returncode != 0:
            self.logger.error(f"Command failed with exit code {process.returncode}")
            return CommandResult(
                process.returncode,
                stdout_combined,
                stderr_combined,
                stack=traceback.format_stack()
            )

        return CommandResult(
            process.returncode,
                stdout_combined,
                stderr_combined
        )

