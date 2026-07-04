# SPDX-License-Identifier: GPL-3.0-or-later

import signal
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
    termios = None  # type: ignore[assignment]
import tempfile
import time
from typing import Callable, Dict, IO, List, Optional, Union, cast
from dar_backup.util import get_logger


def _killpg(pid: int) -> None:
    """Send SIGKILL to the process group of pid.

    Used after start_new_session=True so background children of shell scripts
    (which inherit the stderr pipe fd) are also killed, allowing the stderr
    reader thread to see EOF and exit.
    """
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def is_safe_arg(arg: str) -> bool:
    """Check if a single command-line argument is safe to pass to a subprocess.

    Rejects characters that carry special meaning to a shell, even though this
    codebase always invokes subprocesses in list form (never shell=True) — this is
    defense in depth against an argument that later ends up embedded in a shell
    string (e.g. a generated systemd unit).

    Args:
        arg: A single command-line argument to check.

    Returns:
        True if arg contains none of the disallowed characters, False otherwise.
    """
    # \r enables terminal-overwrite attacks; \x00 truncates strings in C-based programs
    return not re.search(r'[;&|><`$\n\r\x00]', arg)


def sanitize_cmd(cmd: List[str]) -> List[str]:
    """Validate a command-line argument list before it is executed.

    Ensures every element is a string and rejects any that contain a
    shell-dangerous character (see is_safe_arg).

    Args:
        cmd: Command and arguments, e.g. ['dar', '-c', archive_path].

    Returns:
        The same list, unchanged, if every argument is valid.

    Raises:
        ValueError: If cmd is not a list, contains a non-string element, or
            contains an argument rejected by is_safe_arg.
    """

    if not isinstance(cmd, list):
        raise ValueError("Command must be a list of strings")
    for arg in cmd:
        if not isinstance(arg, str):
            raise ValueError(f"Invalid argument type: {arg} (must be string)")
        if not is_safe_arg(arg):
            raise ValueError(f"Unsafe argument detected: {arg}")
    return cmd

def _safe_str(s: Union[str, bytes]) -> str:
    """Return a display-safe string for logging, replacing raw bytes with a placeholder.

    Args:
        s: The value to render, as captured by CommandResult (str in text mode,
            bytes in binary mode).

    Returns:
        s unchanged if it is already a str; otherwise a short placeholder naming
        the byte count, so binary command output never corrupts a log line.
    """
    if isinstance(s, bytes):
        return f"<{len(s)} bytes of binary data>"
    return s


class CommandResult:
    """Outcome of a single CommandRunner.run()/stream_command() invocation.

    Attributes:
        returncode: Exit code of the process, or -1 for a synthesized failure
            (spawn error, timeout, or unexpected exception — see the docstring
            of run() for the exact -1 cases).
        stdout: Captured standard output, up to the caller's capture limit.
        stderr: Captured standard error, up to the caller's capture limit.
        stack: Formatted traceback string when the result represents an
            exception, otherwise None.
        note: Short human-readable annotation, e.g. "stdout truncated", or None.
        stdout_tail: Rolling tail of the last 500 stdout lines, always populated
            even when stdout was truncated by capture_output_limit_bytes — used
            to recover end-of-output summaries (e.g. dar inode statistics) that
            would otherwise be lost.
        stderr_tail: Same as stdout_tail, for stderr.
    """

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
        self.stdout_tail = stdout_tail
        self.stderr_tail = stderr_tail



    def __repr__(self) -> str:
        return (
            f"<CommandResult returncode={self.returncode}\n"
            f"stdout={_safe_str(self.stdout)}\nstderr={_safe_str(self.stderr)}\nstack={self.stack}>"
        )


    def __str__(self) -> str:
        return (
            "CommandResult:\n"
            f"  Return code: {self.returncode}\n"
            f"  Note: {self.note if self.note else '<none>'}\n"
            f"  STDOUT: {_safe_str(self.stdout)}\n"
            f"  STDERR: {_safe_str(self.stderr)}\n"
            f"  Stacktrace: {self.stack if self.stack else '<none>'}"
        )


class CommandRunner:
    """Runs subprocesses (dar, dar_manager, par2, ...) with consistent logging,
    timeout handling, and output capture.

    Every command is executed in list form (never shell=True) after passing
    through sanitize_cmd(), with LC_ALL=C forced so locale-sensitive tool output
    stays parseable. run() blocks until completion (or timeout); stream_command()
    additionally invokes a callback per stdout line as it arrives.

    Attributes:
        logger: Logger for diagnostic messages about the run itself (start/stop,
            errors, timeouts).
        command_logger: Logger that receives the command's own stdout/stderr,
            line by line.
        default_timeout: Seconds to wait before killing the process when a call
            does not pass its own timeout; None disables the timeout entirely.
        default_capture_limit_bytes: Default cap (in bytes) on how much
            stdout/stderr is retained in memory per stream; None means no cap.
    """

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
        self.default_timeout: Optional[int] = default_timeout
        self.default_capture_limit_bytes = default_capture_limit_bytes

        if not self.logger or not self.command_logger:
            self.logger_fallback()

        if self.default_timeout is not None and self.default_timeout <= 0:
            self.default_timeout = None

    def logger_fallback(self) -> None:
        """Replace missing logger/command_logger with temp-file-backed loggers.

        Called from __init__ when the caller did not supply a usable logger and/or
        command_logger, so CommandRunner always has somewhere to write instead of
        raising or silently discarding output. Also resets default_timeout to 30 and
        prints a one-line [WARN] notice (with the temp file paths) to stderr so the
        fallback is visible even before any logging is configured.
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



    def _join_lines(self, lines: List[Union[str, bytes]]) -> Union[str, bytes]:
        """Join captured output chunks, honoring the current text/binary mode.

        stream_output() appends str chunks in text mode and bytes chunks in
        binary mode (never mixed within one run() call), so the cast here
        just tells mypy what self._text_mode already guarantees at runtime.
        """
        if self._text_mode:
            return ''.join(cast(List[str], lines))
        return b''.join(cast(List[bytes], lines))

    def _prefixed_join(self, prefix: str, lines: List[Union[str, bytes]]) -> Union[str, bytes]:
        """Like _join_lines(), but prepends *prefix* (always given as str).

        Kept as one branch (rather than `prefix_value + self._join_lines(lines)`)
        because mypy cannot prove both sides of that `+` pick the same union
        member independently.
        """
        if self._text_mode:
            return prefix + ''.join(cast(List[str], lines))
        return prefix.encode('utf-8') + b''.join(cast(List[bytes], lines))

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
        """Run a command to completion, capturing and logging its output.

        stdout and stderr are read concurrently in background threads while this
        thread blocks on process.wait(), so large output can never deadlock the
        pipes. On any internal failure (unsafe argument, spawn error, timeout, or
        an unexpected exception from the OS) this method does not raise — it
        returns a CommandResult with returncode=-1 describing what happened.

        Args:
            cmd: Command and arguments, e.g. ['dar', '-c', archive_path]. Always
                run in list form (never via a shell); validated by sanitize_cmd()
                before execution.
            timeout: Seconds to wait before killing the process. None uses
                self.default_timeout; a value <= 0 disables the timeout entirely.
            check: If True and the command exits non-zero, the returned
                CommandResult additionally carries a captured stack trace (via
                traceback.format_stack()) for diagnostics. Unlike
                subprocess.run(check=True), this never raises — the caller must
                still inspect returncode.
            capture_output: If True, stdout/stderr are accumulated (up to
                capture_output_limit_bytes) into the returned CommandResult. If
                False, output is still logged (when log_output is True) but not
                retained.
            capture_output_limit_bytes: Per-stream cap, in bytes, on how much of
                stdout/stderr is retained. None uses
                self.default_capture_limit_bytes; a negative value disables the
                cap. A rolling 500-line tail is always kept regardless of this
                limit (see CommandResult.stdout_tail/stderr_tail).
            log_output: If True, every line of stdout/stderr is logged to
                self.command_logger as it arrives.
            text: If True, stdout/stderr are decoded as UTF-8 text; if False,
                raw bytes are kept (see CommandResult.stdout/stderr).
            cwd: Working directory for the subprocess. None uses the caller's
                current directory.
            stdin: File descriptor or special value (e.g. subprocess.DEVNULL)
                passed as the subprocess's stdin.

        Returns:
            A CommandResult with the process's real returncode on normal
            completion, or a synthesized CommandResult with returncode=-1 if the
            command could not be sanitized, spawned, or timed out.

        Raises:
            KeyboardInterrupt: Re-raised (after killing the child process and
                draining the reader threads) if SIGINT arrives while waiting on
                the process.
        """
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
                self.logger.debug("Failed to save terminal attributes", exc_info=True)
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
                cmd = cmd_sanitized  # type: ignore[assignment]

            #command = f"Executing command: {' '.join(cmd)} (timeout={timeout}s)"
            command = f"Executing command: {' '.join(shlex.quote(arg) for arg in cmd)} (timeout={timeout}s)"


            self.command_logger.info(command)
            self.logger.debug(command)

            stdout_lines: List[Union[str, bytes]] = []
            stderr_lines: List[Union[str, bytes]] = []
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

            def stream_output(
                stream: IO[bytes],
                lines: List[Union[str, bytes]],
                level: int,
                truncated_flag: Dict[str, bool],
                tail_deque: deque,
            ) -> None:
                """Read *stream* in 1 KiB chunks, log each complete line, append
                to *lines* up to *capture_output_limit_bytes*, and unconditionally
                append every decoded line to *tail_deque* (capped at maxlen=500).
                The tail is used to recover end-of-output summaries (e.g. dar inode
                stats) that would otherwise be lost when the main capture limit is
                exceeded.

                A partial-line buffer ensures that a line whose bytes straddle a
                1 KiB chunk boundary is assembled before being logged and inserted
                into tail_deque, so neither the command log nor the regex parser
                ever sees a mid-word split."""
                captured_bytes = 0
                partial = ""  # incomplete line carried over from the previous chunk
                try:
                    while True:
                        chunk = stream.read(1024)
                        if not chunk:
                            if partial:
                                if log_output:
                                    self.command_logger.log(level, partial)
                                tail_deque.append(partial)
                            break
                        if self._text_mode:
                            decoded = chunk.decode('utf-8', errors='replace')
                            # Prepend any leftover fragment, split on newlines, and
                            # hold back the final element: it is either "" (trailing
                            # newline) or an incomplete line continued by the next chunk.
                            parts = (partial + decoded).split('\n')
                            partial = parts[-1]
                            complete_lines = parts[:-1]
                            if log_output:
                                for line in complete_lines:
                                    self.command_logger.log(level, line)
                            for line in complete_lines:
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
                # Drain streaming threads so the captured buffers are stable
                # before they are read below.
                for t in threads:
                    t.join(timeout=2)
                duration = time.monotonic() - start_time
                pid = getattr(process, "pid", None)
                log_msg = (
                    f"Command timed out after {timeout} seconds: {' '.join(cmd)} "
                    f"(pid={pid if pid is not None else 'unknown'}, elapsed={duration:.2f}s):\n"
                )
                self.logger.error(log_msg)
                # Prepend the timeout message to the captured stderr.  The
                # previous str.join() misuse dropped the message entirely when
                # stderr was empty and interleaved it between chunks otherwise.
                return CommandResult(
                    -1,
                    self._join_lines(stdout_lines),
                    self._prefixed_join(log_msg, stderr_lines),
                )
            except KeyboardInterrupt:
                # Kill the child process and drain threads so callers can log
                # and flush before the process exits. Without this, background
                # streaming threads block exit and logs never reach disk.
                process.kill()
                for t in threads:
                    t.join(timeout=2)
                raise
            except Exception as e:
                stack = traceback.format_exc()
                process.kill()
                for t in threads:
                    t.join(timeout=2)
                log_msg = f"Command execution failed: {' '.join(cmd)} with error: {e}\n"
                self.logger.error(log_msg)
                return CommandResult(
                    -1,
                    self._join_lines(stdout_lines),
                    self._prefixed_join(log_msg, stderr_lines),
                    stack,
                )

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

            stdout_combined = self._join_lines(stdout_lines)
            stderr_combined = self._join_lines(stderr_lines)

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
                    stack=''.join(traceback.format_stack()),
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

    def stream_command(
        self,
        cmd: List[str],
        line_callback: Callable[[str], None],
        *,
        timeout: Optional[int] = None,
    ) -> CommandResult:
        """Run cmd, calling line_callback once per decoded stdout line.

        Stderr is captured in a background thread (respecting
        self.default_capture_limit_bytes) and every line is logged via
        self.command_logger.  stdout lines are logged and handed to
        line_callback as they arrive; stdout is NOT accumulated in the
        returned CommandResult so callers can collect only what they need.

        Args:
            cmd: Command and arguments.
            line_callback: Invoked in the calling thread for each complete,
                decoded stdout line (no trailing newline).
            timeout: Kill timeout in seconds. None uses self.default_timeout.

        Returns:
            CommandResult with returncode and captured stderr. stdout is always
            empty string.
        """
        if timeout is None:
            timeout = self.default_timeout
        if timeout is not None and timeout <= 0:
            timeout = None

        try:
            cmd = sanitize_cmd(cmd)
        except ValueError as e:
            self.logger.error("Command sanitation failed: %s", e)
            return CommandResult(returncode=-1, stdout="", stderr=str(e))

        cmd_str = " ".join(shlex.quote(arg) for arg in cmd)
        self.command_logger.info("Executing command: %s (timeout=%ss)", cmd_str, timeout)
        self.logger.debug("Executing command: %s (timeout=%ss)", cmd_str, timeout)

        cap = self.default_capture_limit_bytes
        stderr_lines: List[bytes] = []
        stderr_bytes_seen = 0
        lock = threading.Lock()

        cmd_env = os.environ.copy()
        cmd_env["LC_ALL"] = "C"

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=False,
                bufsize=0,
                env=cmd_env,
                start_new_session=True,
            )
        except Exception as e:
            self.logger.error("Failed to start command: %s (error=%s)", cmd_str, e)
            return CommandResult(
                returncode=-1, stdout="", stderr=str(e),
                stack=traceback.format_exc()
            )

        def _read_stderr() -> None:
            nonlocal stderr_bytes_seen
            assert process.stderr is not None
            while True:
                chunk = process.stderr.read(1024)
                if not chunk:
                    break
                decoded = chunk.decode("utf-8", errors="replace")
                self.command_logger.error(decoded.rstrip("\n"))
                with lock:
                    if cap is None:
                        stderr_lines.append(chunk)
                    elif cap > 0 and stderr_bytes_seen < cap:
                        remaining = cap - stderr_bytes_seen
                        if len(chunk) <= remaining:
                            stderr_lines.append(chunk)
                            stderr_bytes_seen += len(chunk)
                        else:
                            stderr_lines.append(chunk[:remaining])
                            stderr_bytes_seen = cap

        stderr_thread = threading.Thread(target=_read_stderr, daemon=True)
        stderr_thread.start()

        try:
            assert process.stdout is not None
            partial = b""
            while True:
                chunk = process.stdout.read(1024)
                if not chunk:
                    if partial:
                        decoded = partial.decode("utf-8", errors="replace")
                        self.command_logger.info(decoded)
                        line_callback(decoded)
                    break
                partial += chunk
                while b"\n" in partial:
                    raw_line, partial = partial.split(b"\n", 1)
                    decoded = raw_line.decode("utf-8", errors="replace")
                    self.command_logger.info(decoded)
                    line_callback(decoded)
            process.stdout.close()

            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _killpg(process.pid)
                stderr_thread.join(timeout=2)
                msg = f"Command timed out after {timeout}s: {cmd_str}"
                self.logger.error(msg)
                return CommandResult(-1, "", msg)
        finally:
            # If the process is still alive (e.g. KeyboardInterrupt arrived while
            # reading stdout), kill its entire process group so that any background
            # children (e.g. `sleep N &` in a shell script) also close their copies
            # of the stderr pipe, allowing the stderr reader thread to exit.
            if process.returncode is None:
                _killpg(process.pid)
            stderr_thread.join()

        stderr_text = b"".join(stderr_lines).decode("utf-8", errors="replace")
        if process.returncode != 0:
            self.logger.error(
                "Command failed returncode=%s: %s", process.returncode, cmd_str
            )
        return CommandResult(process.returncode, "", stderr_text)
