#! /bin/bash

# run install.sh
# copy backup definition TEST --> "A backup definition to verify multiple definitions are handled correctly

BACKUP_DEFINITON_SPACES="A backup definition"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH"/test-setup.sh

source "$SCRIPTDIRPATH"/test-setup.sh
source "$TESTDIR"/conf/dar-backup.conf

# make a second backup definition
cp "$TESTDIR"/backups.d/TEST  "$TESTDIR/backups.d/$BACKUP_DEFINITON_SPACES"

# run FULL backup
"$TESTDIR"/bin/dar-backup.sh --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi
 
# alter backup set
cp "$SCRIPTDIRPATH"/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp "$SCRIPTDIRPATH"/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"

# run DIFF backup
"$TESTDIR"/bin/dar-diff-backup.sh --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# modify a file backed up in the DIFF
touch "$TESTDIR/dirs/include this one/GREENLAND.JPEG"

# run INCREMENTAL backup
"$TESTDIR"/bin/dar-inc-backup.sh  --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
