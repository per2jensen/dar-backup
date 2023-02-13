#! /bin/bash

# test adding achives to catalog for multiple different backup definitions

TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/bin/dar-util.sh"
source "$TESTDIR/conf/dar-backup.conf"

# generate 5 different backups
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST2 
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST3
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST4 
cp "$TESTDIR"/backups.d/TEST "$TESTDIR"/backups.d/TEST5 

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


# populate catalogs with archive data, one at a time
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def TEST --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def TEST2 --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def TEST3 --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def TEST4 --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --backup-def TEST5 --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi



# list the catalogs
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
    echo "List catalog \"$CATALOG\" for backup definition \"$CURRENT_BACKUPDEF\""
    dar_manager  -l --base "$(realpath "$TESTDIR"/archives/"$CATALOG")"
    if [[ $? != "0" ]]; then
      echo ERROR catalog --list for failed "\"$CATALOG\""
      TESTRESULT=1
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)


# check catalogs
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
    echo check catalog "\"$CATALOG\""
    if [[ -e "$TESTDIR"/archives/"$CATALOG" ]]; then 
      dar_manager -c --base "$(realpath "$TESTDIR"/archives/"${CATALOG}")"
      if [[ $? != "0" ]]; then
        echo ERROR catalog DB "\"$CATALOG\"" is not OK
        TESTRESULT=1
      fi
    else
        echo "ERROR  \"${TESTDIR}/archives/${CATALOG}\" does not exist"
        TESTRESULT=1
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)

if [[ "$TESTRESULT" == "0" ]]; then
  log_success "Test case succeeded"
else
  log_fail "Test case failed"
fi

exit "$TESTRESULT"
