#! /bin/bash

# run install.sh
# run dar-backup.sh
# run dar-back.sh once more - expected result is to skip, as an archive already exists

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

# run the test
"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

grep -E "WARN.*?TEST_FULL.*?already exists"  "$TESTDIR/archives/dar-backup.log"
RESULT=$?
if [[  "$RESULT" != "0" ]]; then
    echo existing archive was NOT found
    TESTRESULT=1
fi

exit "$TESTRESULT"
