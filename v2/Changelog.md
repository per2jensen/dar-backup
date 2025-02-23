# dar-backup Changelog

## v2-beta-0.6.12 - 2025-

Github link: [v2-beta-0.6.12](https://github.com/per2jensen/dar-backup/tree/v2-beta-0.6.12/v2)

### Added

- support environment variables in paths, both on command line and in config files
- test case for env vars in config file added
- dar-backup.py does not import sys, use from/import

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

- manager --find-file option added 

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
