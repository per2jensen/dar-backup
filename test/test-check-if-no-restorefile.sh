#! /bin/bash

# Verify that dar-diff finds the newest FULL backup to diff against

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/test-setup.sh

# run the test
$TESTDIR/bin/dar-backup.sh -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi

$TESTDIR/bin/dar-diff-backup.sh -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi



cat $LOG_LOCATION/dar-backup.log|grep "no files found for restore test" > /dev/null 2>&1
if [[ $? != "0" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT


