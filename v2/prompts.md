# Prompts

## unit test setup
Produce a unit test setup based on these input


- all unit-tests are located below /tmp/unit-test/
- test case name is the name of the unit test script (excluding ".py") (i.e test-<something>.py would give a unit test name "test-<something>")
- 1 unit test directory per unit test
- the config template file "../template/backup_script.conf.template" contains the following replacement variables to be replaced
  - @@test-case-name@@ is to be replaced with the name of the test unit script, excluding the ".py"
- on unit test startup
  -- create the unit test directory
  -- create directories in the unit test directory as described in the template config file under section [DIRECTORIES]
  -- replace all placeholders "@@test-case-name@@" and put the resulting config file in the unit test directory

- the unit test must print it's variables with name and valus to console

The config file looks like this:
[DEFAULT]
LOGFILE_LOCATION = /tmp/unit-test/@@test-case-name@@/backup_script.log

[DIRECTORIES]
BACKUP_DIR = /tmp/unit-test/@@test-case-name@@/backups/
TEST_RESTORE_DIR = /tmp/unit-test/@@test-case-name@@/restore/
BACKUP.D_DIR = /tmp/unit-test/@@test-case-name@@/backup.d/

[AGE]
DIFF_AGE = 30
INCR_AGE = 15
