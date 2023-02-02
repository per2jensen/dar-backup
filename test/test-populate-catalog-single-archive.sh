#! /bin/bash

# test adding a specific achive to catalog

TESTRESULT=0
CATALOG=TEST.catalog

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

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

echo "List catalog: $CATALOG"
dar_manager  -l --base "$(realpath "$TESTDIR"/archives/"$CATALOG")"


if [[ "$TESTRESULT" == "0" ]]; then
  echo "Test case succeeded"
fi
exit "$TESTRESULT"
