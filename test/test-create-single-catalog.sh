#! /bin/bash

# test creation of single catalog for an existing backup definition

TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

# generate 5 different backups
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST2 

# create catalog
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir --backup-def TEST
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  TESTRESULT=1
fi

# create another catalog
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir --backup-def TEST2
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  TESTRESULT=1
fi


# create catalog, which already exists
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir --backup-def TEST
if [[ $? != "0" ]]; then
  echo ERROR when trying to create existing catalog
  TESTRESULT=1
fi

# create catalog, for non-existing backup definition
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir --backup-def DOES_NOT_EXIST
if [[ $? == "0" ]]; then
  echo ERROR an error should have happened here
  TESTRESULT=1
fi


if [[ "$TESTRESULT" == "0" ]]; then
  echo "Test case succeeded"
fi
exit "$TESTRESULT"
