# SPDX-License-Identifier: GPL-3.0-or-later

import os

from dar_backup.command_runner import CommandRunner


def test_list_definitions_outputs_backup_d_entries(setup_environment, env):
    extra_defs = ["alpha", "zeta"]
    for name in extra_defs:
        with open(os.path.join(env.backup_d_dir, name), "w") as handle:
            handle.write("# test definition\n")

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ["dar-backup", "--list-definitions", "--config-file", env.config_file]
    process = runner.run(command)

    assert process.returncode == 0
    output_lines = [line for line in process.stdout.splitlines() if line.strip()]
    assert output_lines == sorted(["example"] + extra_defs)
