import logging
import tempfile
import os
from dar_backup.command_runner import CommandRunner


def test_command_runner_executes_successfully():
    # Setup temporary log files
    main_log = tempfile.NamedTemporaryFile(delete=False)
    command_log = tempfile.NamedTemporaryFile(delete=False)

    logger = logging.getLogger("main_logger_test")
    command_logger = logging.getLogger("command_logger_test")
    logger.setLevel(logging.DEBUG)
    command_logger.setLevel(logging.DEBUG)

    main_handler = logging.FileHandler(main_log.name)
    command_handler = logging.FileHandler(command_log.name)

    logger.addHandler(main_handler)
    command_logger.addHandler(command_handler)

    # Run a simple echo command
    runner = CommandRunner(logger=logger, command_logger=command_logger)
    result = runner.run(["echo", "Hello, world!"])

    # Validate the result
    assert result.returncode == 0
    assert "Hello, world!" in result.stdout

    # Check that log files captured the output
    with open(command_log.name) as f:
        command_log_output = f.read()
        assert "Hello, world!" in command_log_output

    with open(main_log.name) as f:
        main_log_output = f.read()
        assert "Executing command" in main_log_output

    # Clean up
    os.unlink(main_log.name)
    os.unlink(command_log.name)


