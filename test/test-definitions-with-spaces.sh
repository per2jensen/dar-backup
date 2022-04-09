#! /bin/bash

# run install.sh
# rename the backup definition from TEST --> "A backup definition"
# run dar-backup.sh
# add file GREENLAND.JPEG to include dir and to the exclude dir
# run dar-diff-backup.sh
# list the FULL, DIFF, INC archives

_RESULT="0"
BACKUP_DEFINITON="A backup definition"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH"/test-setup.sh

source "$SCRIPTDIRPATH"/test-setup.sh
source "$TESTDIR"/conf/dar-backup.conf

mv "$TESTDIR"/backups.d/TEST  "$TESTDIR/backups.d/$BACKUP_DEFINITON"

# run the test
"$TESTDIR"/bin/dar-backup.sh -d "$BACKUP_DEFINITON" --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi
 
dar -l  "$MOUNT_POINT"/"$BACKUP_DEFINITON"_FULL_"$DATE" > "$TESTDIR"/FULL-filelist.txt
echo "dar exit code: $?"


# alter backup set
cp "$SCRIPTDIRPATH"/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp "$SCRIPTDIRPATH"/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"

# run DIFF backup
"$TESTDIR"/bin/dar-diff-backup.sh -d "$BACKUP_DEFINITON" --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi

dar -l  "$MOUNT_POINT"/"$BACKUP_DEFINITON"_DIFF_"$DATE" > "$TESTDIR"/DIFF-filelist.txt
echo dar exit code: $?


# modify a file backed up in the DIFF
touch "$TESTDIR/dirs/include this one/GREENLAND.JPEG"

# run INCREMENTAL backup
"$TESTDIR"/bin/dar-inc-backup.sh -d "$BACKUP_DEFINITON" --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    _RESULT=1
fi

dar -l  "$MOUNT_POINT"/"$BACKUP_DEFINITON"_INC_"$DATE" > "$TESTDIR"/INC-filelist.txt
echo dar exit code: $?


if [[ $_RESULT != "0" ]]; then
    echo "Something went wrong, exiting"
    exit 1
fi


echo .
echo ..
echo ===========================================
echo "cat filelists & logfile, then do checks"
echo ===========================================
echo "FULL dar archive:"
cat "$TESTDIR"/FULL-filelist.txt 
echo "DIFF dar archive:"
cat "$TESTDIR"/DIFF-filelist.txt
echo "Logfile:"
cat "$TESTDIR"/dar-backup.log
echo RESULTS for FULL backup:
# FULL backup
checkExpectLog   "\[Saved\].*?dirs/include this one/Abe.jpg"        "$TESTDIR/FULL-filelist.txt"
checkExpectLog   "\[Saved\].*?dirs/include this one/Krummi.JPG"     "$TESTDIR/FULL-filelist.txt"
checkExpectLog   "\[Saved\].*?dirs/compressable/Lorem Ipsum.txt"    "$TESTDIR/FULL-filelist.txt"
checkDontFindLog "include this one/GREENLAND.JPEG"                  "$TESTDIR/FULL-filelist.txt"
checkDontFindLog "exclude this one/In exclude dir.txt"              "$TESTDIR/FULL-filelist.txt"

echo RESULTS for DIFF backup:
# DIFF backup
checkExpectLog   "\[Saved\].*?dirs/include this one/GREENLAND.JPEG" "$TESTDIR/DIFF-filelist.txt"  
checkDontFindLog "exclude this one/GREENLAND.JPEG"                  "$TESTDIR/DIFF-filelist.txt"  

echo RESULTS for INCREMENTAL backup:
# INC backup
checkExpectLog   "\[Saved\].*?dirs/include this one/GREENLAND.JPEG" "$TESTDIR/INC-filelist.txt"  
NO_SAVED=$(grep -c "\[Saved\]" "$TESTDIR"/INC-filelist.txt)
echo "Number of files saved in INCREMENTAL archive: $NO_SAVED"
if [[  $NO_SAVED != "1"  ]]; then
    echo "more than one file saved in the INCREMENTAL archive"
    TESTRESULT=1
fi

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
