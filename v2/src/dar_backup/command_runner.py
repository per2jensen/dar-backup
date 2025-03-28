import subprocess
import logging
import threading
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from typing import List, Optional

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
        self.logger = logger or logging.getLogger(__name__)
        self.command_logger = command_logger or self.logger
        self.default_timeout = default_timeout

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
        self.logger.debug(f"Executing command: {' '.join(cmd)} (timeout={timeout}s)")

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
            text=text,
            bufsize=1
        )

        stdout_lines = []
        stderr_lines = []

        def stream_output(stream, lines, level):
            for line in iter(stream.readline, ''):
                lines.append(line)
                self.command_logger.log(level, line.strip())
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
