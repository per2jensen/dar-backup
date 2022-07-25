#! /bin/bash

# Check that script does not try to restore a file, if no files are found in backup

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH"/setup.sh

# run the test
"$TESTDIR"/bin/dar-backup.sh -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi

"$TESTDIR"/bin/dar-diff-backup.sh -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi

grep -i "no files found for restore test"  "$LOG_LOCATION"/dar-backup.log > /dev/null 2>&1
if [[ $? != "0" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT


