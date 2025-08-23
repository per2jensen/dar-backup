#! /bin/bash

# test removing 1 entry of an specific archive from it's catalog
#   - multiple different backup definitions
#   - a backup definition name containing spaces

TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/bin/dar-util.sh"
source "$TESTDIR/conf/dar-backup.conf"

# generate 2 different backups
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/"TEST2 with spaces" 


# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi


# do backups
"$TESTDIR/bin/dar-backup.sh" --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi


# add archives for specific backup definition
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def "TEST2 with spaces" --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi

# add all archives in named directory
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi


# remove TEST entry from catalog
_DATE=$(date -I)
dar_manager  -l --base "$(realpath "$TESTDIR"/archives/TEST.catalog)"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

"$TESTDIR/bin/manager.sh"  --remove-specific-archive TEST_FULL_$_DATE   --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

dar_manager  -l --base "$(realpath "$TESTDIR"/archives/TEST.catalog)"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi


#remove TEST2..... entry from catalog
_REALPATH=$(realpath "$TESTDIR"/archives/"TEST2 with spaces.catalog")
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

dar_manager  -l --base "$_REALPATH"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

"$TESTDIR/bin/manager.sh"  --remove-specific-archive "TEST2 with spaces_FULL_$_DATE"   --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

dar_manager  -l --base "$_REALPATH"
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi


if [[ "$TESTRESULT" == "0" ]]; then
  log_success "Test case succeeded"
else
  log_fail "Test case failed"
fi

exit "$TESTRESULT"

