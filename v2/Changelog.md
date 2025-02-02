
## v2-alpha-0.6.6 - 2025-02-02

Github link: [v2-alpha-0.6.6](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.6)

### Added

- Archive catalogs now added to database(s) after a backup has been performed

## v2-alpha-0.6.5 - 2025-01-24

Github link: [v2-alpha-0.6.5](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.5)

### Added

- Changelog.md added

- LICENSE added to the dar-backup wheel package

- Link to Changelog added to PyPi page


## v2-alpha-0.6.4 - 2025-01-23

Github link: [v2-alpha-0.6.4](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.4)

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

Github link: [v2-alpha-0.6.2](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.2)

### Added

- refactor backup functions 

- minor doc fixes 

- par2: process slices by increasing #

- dar-backup --verbose option: print info on par2 generation


## v2-alpha-0.6.1 - 2025-01-05

Github link: [v2-alpha-0.6.1](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.1)

### Added

- FIX timeout error on run_command(). Set a long timeout on "heavy" operations. Default is 30 seconds.

- Log the __str__ of CommandResult on return from run_command()


## v2-alpha-0.6.0 - 2025-01-05

Github link: [v2-alpha-0.6.0](https://github.com/per2jensen/dar-backup/tree/v2-alpha-0.6.0)

### Added

- pytest session logger now used

- if a prereq fails, dar-backup must fail

- document 0.6.0 breaking change

- FIX: ensure run_command() works correctly when a command writes a lot of data to stdout

- updated README with details on --restore-dir option