#! /bin/bash

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# delete "dirs/include this one/Abe.jpg"
# run dar-diff-backup.sh
# list the FULL & DIFF archives

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
mkdir "$TESTDIR/dirs/new-dir"
touch "$TESTDIR/dirs/new-dir/new-file"
rm "$TESTDIR/dirs/include this one/Abe.jpg"
rm "$TESTDIR/dirs/include this one/Abe-link"

# run DIFF backup
"$TESTDIR/bin/dar-diff-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi
echo "Files restored:"
find /tmp/dar-restore/ ! -type d

dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > "$TESTDIR/DIFF-filelist.txt"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi
SAVED_NO=$(grep -E -c "[Saved].*?] +-"  "$TESTDIR/DIFF-filelist.txt")
REMOVED_NO=$(grep -c " REMOVED ENTRY " "$TESTDIR/DIFF-filelist.txt")
printf "TEST_DIFF_$DATE Saved: %s, Removed: %s \n " "$SAVED_NO" "$REMOVED_NO" 


# modify a file backed up in the DIFF
touch "$TESTDIR/dirs/include this one/GREENLAND.JPEG"
rm "$TESTDIR/dirs/new-dir/new-file"
rmdir "$TESTDIR/dirs/new-dir"

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


echo .
echo ..
echo "FULL filelist"
cat "$TESTDIR/FULL-filelist.txt"
echo .
echo "DIFF filelist"
cat "$TESTDIR/DIFF-filelist.txt"
echo .
echo "INC filelist"
cat "$TESTDIR/INC-filelist.txt"
echo .
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
NO_REMOVED=$(grep -c -E "\- REMOVED ENTRY \-" "$TESTDIR/DIFF-filelist.txt")
if [[  $NO_REMOVED == "2"  ]]; then
    echo "ok Number of entries removed: $NO_REMOVED"
else
    echo "error wrong number or removed entries in the DIFF archive"
    TESTRESULT=1
fi


echo RESULTS for INCREMENTAL backup:
# INC backup
checkExpectLog   "\[Saved\].*?dirs/include this one/GREENLAND.JPEG" "$TESTDIR/INC-filelist.txt"  
NO_SAVED=$(grep -c -E "\[Saved\].*?\] +-" "$TESTDIR/INC-filelist.txt")
if [[  $NO_SAVED == "1"  ]]; then
    echo "ok Number of files saved in INCREMENTAL archive: $NO_SAVED"
else
    echo "error more than one file saved in the INCREMENTAL archive"
    TESTRESULT=1
fi
NO_REMOVED=$(grep -c -E "\- REMOVED ENTRY \-" "$TESTDIR/INC-filelist.txt")
if [[  $NO_REMOVED == "1"  ]]; then
    echo "ok Number of entries removed: $NO_REMOVED"
    echo "note: dar should report both removed file and removed dir......."
else
    echo "error wrong number of entries removed in the INCREMENTAL archive"
    TESTRESULT=1
fi

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
