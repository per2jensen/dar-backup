# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import logging
import traceback
import threading
import os
import sys
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from typing import List, Optional
from dar_backup.util import get_logger


class CommandResult:
    def __init__(self, returncode: int, stdout: str, stderr: str, stack: str = None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stack = stack

    def __repr__(self):
        return f"<CommandResult returncode={self.returncode}\nstdout={self.stdout}\nstderr={self.stderr}\nstack={self.stack}>"
    

    def __str__(self):
        return (
            f"CommandResult:\n"
            f"  Return code: {self.returncode}\n"
            f"  STDOUT:\n{self.stdout}\n"
            f"  STDERR:\n{self.stderr}\n"
            f"  Stacktrace:\n{self.stack if self.stack else '<none>'}"
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
        timeout = timeout or self.default_timeout

        command = f"Executing command: {' '.join(cmd)} (timeout={timeout}s)"
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
                    decoded = chunk.decode('utf-8', errors='replace')
                    lines.append(decoded)
                    self.command_logger.log(level, decoded.strip())
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
            self.logger.error(f"Command timed out: {' '.join(cmd)}")
            return CommandResult(-1, ''.join(stdout_lines), ''.join(stderr_lines))
        except Exception as e:
            stack = traceback.format_exc()
            self.logger.error(f"Command execution failed: {' '.join(cmd)} with error: {e}")
            return CommandResult(-1, ''.join(stdout_lines), ''.join(stderr_lines), stack)  

        for t in threads:
            t.join()


        if check and process.returncode != 0:
            self.logger.error(f"Command failed with exit code {process.returncode}")
            return CommandResult(
                process.returncode,
                ''.join(stdout_lines),
                ''.join(stderr_lines),
                stack=traceback.format_stack()
            )

        return CommandResult(
            process.returncode,
            ''.join(stdout_lines),
            ''.join(stderr_lines),
        )

