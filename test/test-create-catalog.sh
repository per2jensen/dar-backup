#! /bin/bash

# test creation of catalog
#   - make 5 backup definitions   
#   - do a backup
#   - create the catalog
#   - populate the catalog with archive data
#   - list catalog
#   - check catalog
#   - restore files

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


# populate catalogs with archive data
"$TESTDIR/bin/manager.sh"   --add-dir  "$TESTDIR"/archives  --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR some or all archives were not added to catalog, exiting
  exit 1
fi

# list the catalog
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


# restore files to temp dirs from catalogs
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}

    TEMPDIR=$(mktemp -d)
    echo restoring "\"$CURRENT_BACKUPDEF\""  to "\"$TEMPDIR\"" from catalog "\"$CATALOG\""
    dar_manager  --base "$(realpath "$TESTDIR"/archives/"$CATALOG")" -e "-R $TEMPDIR" -r "dirs"
    if [[ $? != "0" ]]; then
      echo ERROR dar_manager restore failed
      TESTRESULT=1
    fi
    find "$TEMPDIR" -type f 
    rm -fr "$TEMPDIR"
done  <  <(find "${TESTDIR}"/backups.d -type f -print0)

if [[ "$TESTRESULT" == "0" ]]; then
  log_success "Test case succeeded"
else
  log_fail "Test case failed"
fi

exit "$TESTRESULT"
