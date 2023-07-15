#! /bin/bash

# run install.sh
# copy backup definition TEST --> "A backup definition to verify multiple definitions are handled correctly

BACKUP_DEFINITON_SPACES="A backup definition"

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH"/setup.sh

source "$TESTDIR"/conf/dar-backup.conf

# make a second backup definition
cp "$TESTDIR"/backups.d/TEST  "$TESTDIR/backups.d/$BACKUP_DEFINITON_SPACES"

# make a third bad backup definition name containing "_"
cp "$TESTDIR"/backups.d/TEST  "$TESTDIR/backups.d/CONTAINS_UNDERSCORES"


# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi

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

checkExpectLog   "=> backup discarded"  "$TESTDIR/archives/dar-backup.log"  

echo TEST RESULT: "$TESTRESULT"
exit "$TESTRESULT"
