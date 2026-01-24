import logging
import os
import shutil
from pathlib import Path
from dar_backup.util import setup_logging

def test_dual_logging_trace_suppression(tmp_path):
    """
    Verify that:
    1. The main log file does NOT contain stack traces.
    2. The trace log file DOES contain stack traces.
    """
    log_file = tmp_path / "test.log"
    command_log = tmp_path / "test_cmd.log"
    trace_log = tmp_path / "test.trace.log"

    # Reset logger handlers to avoid interference from other tests
    logger = logging.getLogger("main_logger")
    logger.handlers = []

    # Setup logging
    logger = setup_logging(
        str(log_file),
        str(command_log),
        log_level="info",
        log_to_stdout=False
    )

    # Log an exception
    try:
        raise ValueError("This is a test error")
    except ValueError:
        logger.error("Caught an exception", exc_info=True)

    # Flush handlers
    for handler in logger.handlers:
        handler.flush()
        handler.close()

    # Read logs
    main_log_content = log_file.read_text()
    trace_log_content = trace_log.read_text()

    # Assertions
    assert "Caught an exception" in main_log_content
    assert "ValueError: This is a test error" not in main_log_content, "Main log should NOT have stack trace"
    
    assert "Caught an exception" in trace_log_content
    assert "ValueError: This is a test error" in trace_log_content, "Trace log SHOULD have stack trace"
    assert "Traceback (most recent call last):" in trace_log_content

def test_dual_logging_debug_level(tmp_path):
    """
    Verify that:
    1. The main log file respects the log level (INFO).
    2. The trace log file captures DEBUG messages regardless.
    """
    log_file = tmp_path / "debug_test.log"
    command_log = tmp_path / "debug_test_cmd.log"
    trace_log = tmp_path / "debug_test.trace.log"

    # Reset logger handlers
    logger = logging.getLogger("main_logger")
    logger.handlers = []

    # Setup logging with level INFO
    logger = setup_logging(
        str(log_file),
        str(command_log),
        log_level="info",
        log_to_stdout=False
    )

    logger.info("Info message")
    logger.debug("Debug message")

    # Flush handlers
    for handler in logger.handlers:
        handler.flush()
        handler.close()

    main_content = log_file.read_text()
    trace_content = trace_log.read_text()

    # Main log should have INFO but not DEBUG
    assert "Info message" in main_content
    assert "Debug message" not in main_content

    # Trace log should have BOTH
    assert "Info message" in trace_content
    assert "Debug message" in trace_content
