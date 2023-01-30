#! /bin/bash

# test creation of catalog
#   - do a backup
#   - create the catalog
#   - populate the catalog with archive data
#   - restore files

TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

# do a backup
"$TESTDIR/bin/dar-backup.sh" -d TEST --local-backup-dir
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# create catalog
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi

# populate catalog with archive data
"$TESTDIR/bin/manager.sh"   --add-dir  "$MOUNT_POINT"  --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi

# list the catalog
dar_manager  -l --base "$TESTDIR"/archives/dar-backup.catalog
if [[ $? != "0" ]]; then
  echo ERROR catalog --list failed, exiting
  exit 1
fi

# check catalog DB
dar_manager  -c --base "$TESTDIR"/archives/dar-backup.catalog
if [[ $? != "0" ]]; then
  echo ERROR catalog DB is not OK, exiting
  exit 1
fi

# restore files to /tmp/dir/
TEMPDIR=$(mktemp -d)
echo restoring to \"$TEMPDIR\"
dar_manager  --base "$TESTDIR"/archives/dar-backup.catalog -e "-R $TEMPDIR" -r "dirs"
if [[ $? != "0" ]]; then
  echo ERROR dar_manager restore failed
  exit 1
fi

exit "$TESTRESULT"
