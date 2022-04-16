#! /bin/bash -x

# run install.sh
# run dar-backup.sh
# on purpose introduce "bitrot", 34000 random chars (very close to 5% bitrot) 10k into the archive
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
# 30000 random chars, 10kB into the archive
echo "==> introduce bitrot"
BLOCKSIZE=34000
BITROT=/tmp/bitrot-block.txt
tr -dc 'a-z0-9' < /dev/random|head -c${BLOCKSIZE} > "$BITROT"
echo "BITROT data:"
cat "$BITROT"
ARCHIVEFILE=$TESTDIR/archives/TEST_FULL_${DATE}.1.dar
ls -l $ARCHIVEFILE
cp $ARCHIVEFILE ${ARCHIVEFILE}.org
tr -d '\n' < "$BITROT"|dd of="$ARCHIVEFILE" bs=${BLOCKSIZE} seek=$((10*1024)) oflag=seek_bytes conv=notrunc
ls -l $ARCHIVEFILE
diff $ARCHIVEFILE ${ARCHIVEFILE}.org


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
