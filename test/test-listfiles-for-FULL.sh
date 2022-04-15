#! /bin/bash

# Test that the listFiles shows same number as files actually backed up

SCRIPTPATH=$(realpath $0)
SCRIPTDIRPATH=$(dirname $SCRIPTPATH)
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/setup.sh

# run FULL backup
$TESTDIR/bin/dar-backup.sh -d TEST --local-backup-dir
failOnError $?
echo "MOUNT_POINT: ${MOUNT_POINT}"
NO_BACKEDUP=$(dar -vt -l "$MOUNT_POINT/TEST_FULL_$DATE" |grep "\[Saved\]"|grep -v " d......... "|wc -l)

# run listFiles
$TESTDIR/bin/dar-backup.sh -d TEST --list-files --local-backup-dir
failOnError $?
NO_LISTED=$(cat /tmp/dar-FULL-filelist.txt|grep -E -i "adding file|adding symlink"|wc -l)

if [[ $NO_BACKEDUP != $NO_LISTED ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT

