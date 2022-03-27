#! /bin/bash

# Verify a link is restored and handled correctly by scriot

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/test-setup.sh

$TESTDIR/bin/dar-backup.sh -d TEST $DRY_RUN --local-backup-dir
if [[ $? != "0" ]]; then
    exit 1
fi


mkdir /tmp/dar-308582
touch /tmp/dar-308582/a-file.txt

ln -s /tmp/dar-308582/a-file.txt  $TESTDIR/dirs/a-file

# run DIFF backup
$TESTDIR/bin/dar-diff-backup.sh -d TEST $DRY_RUN --local-backup-dir
if [[ $? != "0" ]]; then
    exit 1
fi

dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > $TESTDIR/DIFF-filelist.txt
if [[ $? != "0" ]]; then
    exit 1
fi

checkExpectLog          "\[Saved\].*?dirs/a-file" "$TESTDIR/DIFF-filelist.txt" 
checkExpectSymbolicLink "$TESTDIR/dirs/a-file"

echo TEST RESULT: $TESTRESULT

rm -fr /tmp/dar-308582

exit $TESTRESULT
