import logging
import os
import shutil
import tempfile
import pytest
from dar_backup.util import setup_logging, get_logger
from dar_backup.command_runner import CommandRunner

def test_trace_logging_captures_all_levels_and_commands():
    # Setup temp directories and files
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "main.log")
        command_log = os.path.join(tmpdir, "commands.log")
        trace_log = os.path.join(tmpdir, "main.trace.log")
        
        # Reset loggers to ensure clean state
        logging.getLogger("main_logger").handlers = []
        logging.getLogger("command_output_logger").handlers = []
        
        # Setup logging with trace enabled
        logger = setup_logging(
            log_file=log_file,
            command_output_log_file=command_log,
            log_level="info",
            trace_log_file=trace_log,
            trace_log_max_bytes=1024 * 1024,
            trace_log_backup_count=1
        )
        
        # 1. Log INFO and DEBUG messages
        logger.info("This is an INFO message")
        logger.debug("This is a DEBUG message")
        
        # 2. Log an exception
        try:
            raise ValueError("Test Exception")
        except ValueError:
            logger.error("An error occurred", exc_info=True)
            
        # 3. Run a command and capture output
        runner = CommandRunner(logger=logger)
        # Use a simple echo command
        runner.run(["echo", "Hello from command"], log_output=True)
        
        # Verify Trace Log Content
        assert os.path.exists(trace_log)
        with open(trace_log, "r") as f:
            content = f.read()
            
        # Check INFO message (should be in trace)
        assert "This is an INFO message" in content
        
        # Check DEBUG message (should be in trace even if main log level is INFO)
        assert "This is a DEBUG message" in content
        
        # Check Exception Traceback
        assert "ValueError: Test Exception" in content
        assert "Traceback (most recent call last):" in content
        
        # Check Command Output (should be in trace because we added trace_handler to secondary_logger)
        assert "Hello from command" in content

def test_trace_log_rotation():
    with tempfile.TemporaryDirectory() as tmpdir:
        log_file = os.path.join(tmpdir, "rotate.log")
        command_log = os.path.join(tmpdir, "rotate_cmd.log")
        trace_log = os.path.join(tmpdir, "rotate.trace.log")
        
        # Reset loggers
        logging.getLogger("main_logger").handlers = []
        logging.getLogger("command_output_logger").handlers = []

        # Setup with small size for rotation
        logger = setup_logging(
            log_file=log_file,
            command_output_log_file=command_log,
            trace_log_file=trace_log,
            trace_log_max_bytes=100, # Very small size
            trace_log_backup_count=1
        )
        
        # Write enough data to trigger rotation
        # Each line needs to be long enough or many lines
        for i in range(20):
            logger.debug(f"Line {i} " * 10)
            
        # Verify rotation happened
        assert os.path.exists(trace_log)
        assert os.path.exists(trace_log + ".1")

