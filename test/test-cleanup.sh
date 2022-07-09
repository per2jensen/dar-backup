#! /bin/bash

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# run dar-diff-backup.sh
# cleanup DIFF and INC archives


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
echo "non directories restored:"
find /tmp/dar-restore/ ! -type d
 
dar -l  "$MOUNT_POINT/TEST_FULL_$DATE" > "$TESTDIR/FULL-filelist.txt"
echo dar exit code: $?

# alter backup set
cp "$SCRIPTDIRPATH/GREENLAND.JPEG" "$TESTDIR/dirs/include this one/"
cp "$SCRIPTDIRPATH/GREENLAND.JPEG" "$TESTDIR/dirs/exclude this one/"

# run DIFF backup
"$TESTDIR/bin/dar-diff-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi
echo "non directories restored:"
find /tmp/dar-restore/ ! -type d

dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > "$TESTDIR/DIFF-filelist.txt"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# modify a file backed up in the DIFF
touch "$TESTDIR/dirs/include this one/GREENLAND.JPEG"

# run INCREMENTAL backup
"$TESTDIR/bin/dar-inc-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi
echo "non directories restored:"
find /tmp/dar-restore/ ! -type d

dar -l  "$MOUNT_POINT/TEST_INC_$DATE" > "$TESTDIR/INC-filelist.txt"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi


if [[ $TESTRESULT != "0" ]]; then
    echo "Something went wrong, exiting"
    exit 1
fi


# set DIFF_AGE and INC_AGE so that INCs are cleaned up
sed -i s/INC_AGE.*/INC_AGE=-1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/DIFF_AGE.*/DIFF_AGE=0/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir

grep "clean up:" "$TESTDIR"/archives/dar-backup.log|grep DIFF
if [[ "$?" != "1" ]]; then
  echo a DIFF archive was found, should only have been INCs
  exit 1
fi


# set DIFF_AGE and INC_AGE so that DIFFs are cleaned up
sed -i s/DIFF_AGE.*/DIFF_AGE=-1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/INC_AGE.*/INC_AGE=0/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir

COUNT=$(grep -c "clean up:" "$TESTDIR"/archives/dar-backup.log)
if [[ "$COUNT" != "6" ]]; then
  echo total number of files deleted expected to be 6
  exit 1
fi


