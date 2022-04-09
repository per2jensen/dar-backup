#! /bin/bash

# Verify a symbolic link is restored and handled correctly by script
# don't follow the link, restore the link itself

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH"/test-setup.sh

"$TESTDIR"/bin/dar-backup.sh -d TEST --local-backup-dir
if [[ $? != "0" ]]; then
    exit 1
fi


NEWDIR=/tmp/dar-395043
rm -fr "$NEWDIR"
mkdir "$NEWDIR"
touch "$NEWDIR"/a-file.txt

ln -s "$NEWDIR"/a-file.txt  "$TESTDIR"/dirs/a-file

# run DIFF backup
"$TESTDIR"/bin/dar-diff-backup.sh -d TEST --local-backup-dir
if [[ $? != "0" ]]; then
    exit 1
fi

dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > "$TESTDIR"/DIFF-filelist.txt
if [[ $? != "0" ]]; then
    exit 1
fi

checkExpectLog          "\[Saved\].*?dirs/a-file" "$TESTDIR/DIFF-filelist.txt" 
checkExpectSymbolicLink "$TESTDIR/dirs/a-file"

echo TEST RESULT: "$TESTRESULT"

rm -fr "$NEWDIR"

exit "$TESTRESULT"
