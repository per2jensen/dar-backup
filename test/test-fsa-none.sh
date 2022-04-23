#! /bin/bash

# test that the --fsa-scope-none option works 

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# run dar-diff-backup.sh
# list the FULL & DIFF archives

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

# run the test
"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir --fsa-scope-none
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
"$TESTDIR/bin/dar-diff-backup.sh" -d TEST --local-backup-dir  --fsa-scope-none
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
"$TESTDIR/bin/dar-inc-backup.sh" -d TEST --local-backup-dir --fsa-scope-none
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


echo .
echo ..
echo ===========================================
echo "cat filelists & logfile, then do checks"
echo ===========================================
echo "FULL dar archive:"
cat "$TESTDIR/FULL-filelist.txt"
echo "DIFF dar archive:"
cat "$TESTDIR/DIFF-filelist.txt"
echo "Logfile:"
cat "$LOG_LOCATION/dar-backup.log"
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
NO_SAVED=$(grep -c "\[Saved\]" "$TESTDIR/INC-filelist.txt")
if [[  $NO_SAVED == "1"  ]]; then
    echo "ok Number of files saved in INCREMENTAL archive: $NO_SAVED"
else
    echo "error more than one file saved in the INCREMENTAL archive"
    TESTRESULT=1
fi

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
