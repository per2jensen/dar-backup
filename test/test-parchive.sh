#! /bin/bash

# run install.sh
# run dar-backup.sh
# on purpose introduce "bitrot", 4k random chars 10k into the archive
# repair via "par2 r"
# verify repair is successful using "dar -t" and "par2 v"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

TESTRESULT=0

# do a backup
"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir > /dev/null
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# introduce "bitrot"
# 4096 random chars, 10kB into the archive
echo "==> introduce bitrot"
BITROT=$(tr -dc 'a-z0-9' < /dev/random|head -c4096)
printf "BITROT data:\n%s\n" "$BITROT"
ARCHIVEFILE=$TESTDIR/archives/TEST_FULL_${DATE}.1.dar
echo "$BITROT"|tr -d '\n'|dd of="$ARCHIVEFILE" bs=4096 seek=$((10*1024))  oflag=seek_bytes conv=notrunc

# does dar detect the changes
echo "==> dar test archive"
dar -t "$TESTDIR/archives/TEST_FULL_${DATE}"
RESULT=$?
if [[ $RESULT == "0" ]]; then
    echo "dar did NOT detect bitrot"
    TESTRESULT=1
fi

# does par2 detect bitrot
echo "==> par2 verify archive"
par2 v -q "$ARCHIVEFILE" 
RESULT=$?
if [[ $RESULT == "0" ]]; then
    echo "par2 did NOT detect bitrot"
    TESTRESULT=1
fi

# fix bitrot
echo "==> par2 repair archive"
par2 r -q "$ARCHIVEFILE"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "par2 did NOT repair bitrot"
    TESTRESULT=1
fi

# test archive with dar
echo "==> dar test archive"
dar -t "$TESTDIR/archives/TEST_FULL_${DATE}"   > /dev/null
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "archive was not repaired"
    TESTRESULT=1
fi

# test archive with par2
echo "==> par2 verify archive"
par2 v -q "$ARCHIVEFILE"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "par2 did NOT repair bitrot"
    TESTRESULT=1
fi

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
