#! /bin/bash

# run install.sh
# run dar-backup.sh
# on purpose introduce "bitrot"
# try to repair via Parchive
# verify repair is successful

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

TESTRESULT=0

# run the test
"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# introduce "bitrot"
ARCHIVEFILE=$TESTDIR/archives/TEST_FULL_${DATE}.1.dar
echo "__PER-JENSEN__æøå" |dd of="$ARCHIVEFILE" bs=1 seek=$((10*1024)) conv=notrunc

# does dar detect the changes
dar -t $TESTDIR/archives/TEST_FULL_${DATE} 
RESULT=$?
if [[ $RESULT == "0" ]]; then
    echo "dar did NOT detect bitrot"
    TESTRESULT=1
fi

# does par2 detect bitrot
par2 v "$ARCHIVEFILE" 
RESULT=$?
if [[ $RESULT == "0" ]]; then
    echo "par2 did NOT detect bitrot"
    TESTRESULT=1
fi

# fix bitrot
par2 r "$ARCHIVEFILE"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "par2 did NOT repair bitrot"
    TESTRESULT=1
fi

# test archive with dar
dar -t $TESTDIR/archives/TEST_FULL_${DATE} 
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "archive was not repaired"
    TESTRESULT=1
fi

# test archive with par2
par2 v "$ARCHIVEFILE" 
RESULT=$?
if [[ $RESULT != "0" ]]; then
    echo "par2 did NOT repair bitrot"
    TESTRESULT=1
fi


echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
