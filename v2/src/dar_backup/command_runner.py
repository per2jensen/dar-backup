import subprocess
import logging
import threading
import os
import sys
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from typing import List, Optional
from dar_backup.util import get_logger


class CommandResult:
    def __init__(self, returncode: int, stdout: str, stderr: str):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr

    def __repr__(self):
        return f"<CommandResult returncode={self.returncode}>"


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

        #log the command to be executed
        command = f"Executing command: {' '.join(cmd)} (timeout={timeout}s)"
        self.command_logger.info(command) # log to command logger
        self.logger.debug(command)        # log to main logger if "--log-level debug"

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=False,
            bufsize=-1
        )

        stdout_lines = []
        stderr_lines = []


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

        for t in threads:
            t.join()

        if check and process.returncode != 0:
            self.logger.error(f"Command failed with exit code {process.returncode}")

        return CommandResult(process.returncode, ''.join(stdout_lines), ''.join(stderr_lines))
