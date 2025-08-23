<!-- markdownlint-disable MD024 -->
# dar-backup Changelog

## v2-beta-0.8.4 - 2025-08-23

Github link: [v2-beta-0.8.4](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.8.4/v2)

### Added

- Option '-D' only added when restoring FULL backups.
  - A test case on [my dar-backup-image repo](https://github.com/per2jensen/dar-backup-image) does not delete a lone file in a directory if -D is used restoring from a DIFF.

## v2-beta-0.8.3 - 2025-08-23

Github link: [v2-beta-0.8.3](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.8.3/v2)

### Added

- Dar-backup now deletes files if noted as "removed" in the archive catalog for DIFF and INCR backups.
  - This ensures a restore of a FULL + DIFF + INCR matches the files in the source directories.
  - Options '-wa' & '-/ Oo'  added to the restore command.

## v2-beta-0.8.2 - 2025-07-17

Github link: [v2-beta-0.8.2](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.8.2/v2)

### Added

- Security hardening: CommandRunner now performs strict command-line sanitization
  - Disallows potentially dangerous characters (e.g. ;, &, |) in command arguments
  - Prevents injection-style misuse when restoring specific files or invoking custom commands

- Documentation:
  - New [README section](https://github.com/per2jensen/dar-backup?tab=readme-ov-file#limitations-on-file-names-with-special-characters) explains filename restrictions and safe workarounds (e.g. restoring directly with dar, if needed)
  - Includes a Markdown table listing all disallowed characters

- Test suite:
  - Existing test cases updated to comply with the new sanitization rules
  - Additional tests ensure CommandRunner handles large binary output and edge cases cleanly

## v2-beta-0.8.1 - 2025-07-16

Github link: [v2-beta-0.8.1](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.8.1/v2)

### Added

- FIX: runner now logs an error and fills more data into the returned CommandResult.

## v2-beta-0.8.0 - 2025-06-13

Github link: [v2-beta-0.8.0](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.8.0/v2)

### Added

- Modified clone dashboard generator to produce easier to read dashboard and be more robust.
- Dir_traversal sanitation: clean_log.py now only accepts files in configured log directory to `--file` option.

## v2-beta-0.7.2 - 2025-06-07

Github link: [v2-beta-0.7.2](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.7.2/v2)

### Added

- Refactored build system, so all dependencies are kept in `pyproject.toml`. The dependencies are separated  into dev, packaging and delivery phases.
- Use `build.sh` to setup pytest environment in Github workflow.

  - Do the same to get a development environment going.

- Added 2 new optional params to control log file roll.
- Enrolling into [Snyk code checker](https://snyk.io/code-checker/) and learning how to work with it.
  
  - Snyk helped pointing out vulnerable versions of some packages used.
  - Input sanitation started, there is room for improvement.

## v2-beta-0.7.1 - 2025-05-22

Github link: [v2-beta-0.7.1](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.7.1/v2)

### Added

- Quick Guide with reworked `demo` program.
- util.get_invocation_command_line() used to print command line.
- Installer to setup directories and catalog databases as prescribed in config file.
- Documentation on dar-backup --selection option improved.
- README.md clean up, signing section now with multiple collabsible sections.
- Install instructions fixed after trial in fresh utuntu VM.
- Small license display refac.
- .deb package for Ubuntu can now be built (draft quality)

  -- DO NOT use unless for testing on an empty VM
  -- no real checking if this package aligns with Ubuntu's package requirements
  -- package `inputimeout` is installed via pip as Ubuntu does not have a .deb

- SPDX license header added to many files
- Action + program to capture cloning stats and store them in v2/doc directory. Includes a badge.

  -- annotate new daily max number of clones
  -- Celebration badge when certain clones numbers are hit (just for fun)

- Action + program to generate 12 weeks cloning dashboard (a PNG) with annotation
- Tweaked the auto completion setup in .bashrc, it stopped working for me unknown reasons (needs some looking into)
- --verbose now affects the startup banner. Now it is printed only if --verbose is given

## v2-beta-0.6.20.1 - 2025-05-04

Github link: [v2-beta-0.6.20.1](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.20.1/v2)

### Added

- FIX: bash/zsh completers fixed to support MANAGER_DB_DIR config if set
- `cleanup` and `manager` completer now sorts archives by \<backup-definition> and \<archive date> (so not using \<type>)

## v2-beta-0.6.20 - 2025-05-03

Github link: [v2-beta-0.6.20](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.20/v2)

### Added

- show_version() moved to util and tests for dar-backup, manager and cleanup
- startup informational messages now works the same across the scripts
- Improved ConfigSettings class to handle optional configuration keys

  -- test cases added

- Optional config parameter: MANAGER_DB_DIR, ideally to point to another disk for safe keeping backup catalogs

  -- test cases added

## v2-beta-0.6.19 - 2025-04-21

Github link: [v2-beta-0.6.19](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.19/v2)

### Added

- removed a BackupError in the verify() to reduce noise in logs and let the rest of "compares" run.
- Added bash and zsh auto completion for a nicer CLI experience.
  
  -- See [README for details](https://github.com/per2jensen/dar-backup?tab=readme-ov-file#shell-autocompletion)  

- Improvement to command_runner.run(), more robust decoding

- Manager --add-specific-archive now gives a prompt with a warning if user attempts to add a catalog that breaks chronology. The user is allowed to go forward and ignore the warning or can choose to abort. The program times out after a little while and discards the operation.

## v2-beta-0.6.18 - 2025-04-05

Github link: [v2-beta-0.6.18](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.18/v2)

### Added

- setup of package signing using key: `dar-backup@pm.me` added.
  -- key created
  -- docs updated
  -- release script created
  -- key added top OpenPGP.org key server
  -- pypi setup modified and set to use the new Signing subkey
- README.md and Changelog.md now included in the wheel and installed on `pip install dar-backup`
- new options to make it easy to find docs (--readme, --readme-pretty, --changelog, --changelog-pretty)
- Generate systemd user units, and optionally install them
- Progress bar and status line showing current directory being backed up (thanks to `rich`)
- Pytest coverage now computed and displayed on Github
- 2 code improvements and multiple cleanup tests added
- Many test cases added, manager now in good pytest shape

## v2-beta-0.6.17 - 2025-03-29

Github link: [v2-beta-0.6.17](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.17/v2)

### Added

- prereq and postreq logging now using debug level.
- documentation: updates, links and fixes. Test coverage result included.
- multiple .info() modified to debug() to keep the log file easily readable.
- FIX: test case found an error in config_setting init
- more testcases to expand coverage
- code reorganization. util.run_command() replaced with CommandRunner class.

## v2-beta-0.6.16- 2025-03-22

Github link: [v2-beta-0.6.16](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.16/v2)

### Added

- The generated filtered darrc file from `-suppress-dar-msg` now removed at program exit. Test case modified to check for removal
- README.md updated to reflect recent changes
- `cleanup` now requires a confirmation to delete a _FULL_ archive (using the option: --cleanup-specific-archives)
- Module `inputimeout` used and installed into the venv, when `dar-backup` is installed
- Much more clean log file in default config, use `--verbose` for more information, `--log-level debug` for even more
- Added option  --test-mode to `cleanup` to run tests verifying that FULL archives are deleted only if the user answers "yes"

## v2-beta-0.6.15- 2025-03-16

Github link: [v2-beta-0.6.15](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.15/v2)

### Added

- Restore test details now logged only if args.verbose is set (less clutter in log file)
- `--log-stdout` now does not show run_command() output from program being run
- Report error and exit code `1` if manager did not add an archive to it's database

## v2-beta-0.6.14 - 2025-03-02

Github link: [v2-beta-0.6.14](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.14/v2)

### Added

- `dar` catalog in xml now parsed correctly, test case added
- error handling improved, --verbose print terse list of errors on exit, test case added
- test cases simulating disk corruption being worked on, not yet in test suite
- postreq test case improved
- manager is not given "-ai" when adding catalogs (might give an issue on cloud backups, investigate....)

## v2-beta-0.6.13.1 - 2025-02-25

Github link: [v2-beta-0.6.13.1](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.13.1/v2)

### FIX

- remove a leftover print() in run_command()

## v2-beta-0.6.13 - 2025-02-25

Github link: [v2-beta-0.6.13](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.13/v2)

### Added

- README.md now good MarkDown, fixed reference section
- Changelog.md now good MarkDown
- --suppress-dar-msg option added (one way to cancel the verbosity options in .darrc)
- separate log file for command outputs. This keeps the core dar-backup.log more readable

## v2-beta-0.6.12 - 2025-02-23

Github link: [v2-beta-0.6.12](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.12/v2)

### Added

- support environment variables in paths, both on command line and in config files
- test case for env vars in dar-backup.conf added
- test case for ~ in dar-backup.conf added
- dar-backup.py does not import sys, use from/import of specific functions
- fix handling of missing config file
- if config file, .darrc or backup definition not found, return 127
- installer added to demo dar-back, installs demo config and backup definition

## v2-beta-0.6.11 - 2025-02-23

Github link: [v2-beta-0.6.11](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.11/v2)

### Added

- run_command() fixed to handle missing command. Test case added.
- refactoring xml parsing of dar list output. From recursive to iterating the xml document.
- a bit more input verification to ensure the given config file actually exists.
- README.md updated with useful information from v1 + some tweaks

## v2-beta-0.6.10 - 2025-02-22

Github link: [v2-beta-0.6.10](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.10/v2)

### Added

- unit test verifying no compression of many compressed file formats
- README.md lint fixes + a TOC

## v2-beta-0.6.9 - 2025-02-21

Github link: [v2-beta-0.6.9](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.9/v2)

### Added

- clean-log script added (can remove much of `dar's` output that might be put in the dar-backup log file)
- ChatGPT generated pytest cases

## v2-beta-0.6.8 - 2025-02-13

Github link: [v2-beta-0.6.8](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.8/v2)

### Added

- switching from alpha --> beta status
- manager --list-archive-contents added

## v2-alpha-0.6.7 - 2025-02-11

Github link: [v2-alpha-0.6.7](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.7/v2)

### Added

- Cleanups now remove catalogs from the catalog databases

## v2-alpha-0.6.6 - 2025-02-02

Github link: [v2-alpha-0.6.6](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.6/v2)

### Added

- Archive catalogs now added to database(s) after a backup has been performed

## v2-alpha-0.6.5 - 2025-01-24

Github link: [v2-alpha-0.6.5](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.5/v2)

### Added

- Changelog.md added
- LICENSE added to the dar-backup wheel package
- Link to Changelog added to PyPi page

## v2-alpha-0.6.4 - 2025-01-23

Github link: [v2-alpha-0.6.4](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.4/v2)

### Added

- Stdout & stderr from called programs are streamed to logfile in real time. This makes it easier to see if a very long running process is still active.
- .darrc: -vd & -vf options enabled, so `dar` emits information when entering a directory and print some stats when leaving it
- manager --remove-specific-archive option added
- manager --list-catalog option added
- improved tests for manager
- manager --add-dir option added
- verify slices are par2 processed by increasing slice number
- reorg unit test,
- added test for --restore-dir

## v2-alpha-0.6.2 - 2025-01-12

Github link: [v2-alpha-0.6.2](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.2/v2)

### Added

- refactor backup functions
- minor doc fixes
- par2: process slices by increasing #
- dar-backup --verbose option: print info on par2 generation

## v2-alpha-0.6.1 - 2025-01-05

Github link: [v2-alpha-0.6.1](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.1/v2)

### Added

- FIX timeout error on run_command(). Set a long timeout on "heavy" operations. Default is 30 seconds.
- Log the __str__ of CommandResult on return from run_command()

## v2-alpha-0.6.0 - 2025-01-05

Github link: [v2-alpha-0.6.0](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.0/v2)

### Added

- pytest session logger now used
- if a prereq fails, dar-backup must fail
- document 0.6.0 breaking change
- FIX: ensure run_command() works correctly when a command writes a lot of data to stdout
- updated README with details on --restore-dir option

<!-- markdownlint-enable MD024 -->