#! /bin/bash

# Run diff without a full, expect an exit code = 100

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/setup.sh

# run DIFF backup
$TESTDIR/bin/dar-diff-backup.sh -d TEST $DRY_RUN --local-backup-dir
if [[ $? != "100" ]]; then
  echo DIFF backup did not fail as expected, due to no FULL backup found
  TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT
