#! /bin/bash

# Verify that dar-diff finds the newest FULL backup to diff against

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/test-setup.sh

touch $TEST_ARCHIVE_DIR/TEST_FULL_2019-01-01.1.dar
touch $TEST_ARCHIVE_DIR/TEST_FULL_2021-12-31.1.dar
touch $TEST_ARCHIVE_DIR/TEST_FULL_2021-22-33.1.dar  #not a valid date
touch $TEST_ARCHIVE_DIR/TEST_FULL_2099-12-31.1.dar  # future date
echo files in archive directory:
ls -lh $MOUNT_POINT

# run DIFF backup
$TESTDIR/bin/dar-diff-backup.sh -d TEST $DRY_RUN --local-backup-dir > $TESTDIR/dar-output.txt

egrep "NEWEST archive: +TEST_FULL_2099-12-31" $TESTDIR/dar-output.txt
if [[ $? == "0" ]]; then
    echo "script DID use the correct (fake) archive to diff against"
else
    echo "ERROR script did not did find the archive: TEST_FULL_2099-12-31.1.dar"
    TESTRESULT = 1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT
