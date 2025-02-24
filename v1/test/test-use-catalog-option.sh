#! /bin/bash

# test if --use-catalogs option works as intended

TESTRESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

echo "Remove the auto created catalogs by setup.sh"
rm -f "$TESTDIR"/archives/*.catalog
find "$TESTDIR" -name "*.catalog"


# do backups
"$TESTDIR/bin/dar-backup.sh" --local-backup-dir  --verbose
RESULT=$?
if [[ $RESULT != "1" ]]; then  # dar-backup should report the missing catalog error
    TESTRESULT=1
fi

echo "Find catalogs, there should not be any...."
find "$TESTDIR" -name "*.catalog"


# list the catalog - there should not be any
echo "List all catalogs"
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG=${CURRENT_BACKUPDEF}${CATALOG_SUFFIX}
    if [[ -e "$TESTDIR"/archives/"$CATALOG" ]]; then 
        echo "ERROR - there should not be any catalog at this point in time"
        TESTRESULT=1 # there should not be any catalog
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)


echo "Now do backup with catalog enabled"

rm -f "$TESTDIR"/archives/TEST_FULL_*

# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi

# do backups
"$TESTDIR/bin/dar-backup.sh" --use-catalogs --local-backup-dir --verbose
RESULT=$?
if [[ $RESULT != "0" ]]; then
    TESTRESULT=1
fi

# list the catalog
echo "List catalogs"
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG="${CURRENT_BACKUPDEF}"${CATALOG_SUFFIX}
    _ARCHIVENAME="${CURRENT_BACKUPDEF}"_FULL_$(date -I)
    echo "List catalog \"$CATALOG\" for archive: \"$_ARCHIVENAME\""
    dar_manager  -l --base "$(realpath "$TESTDIR"/archives/"$CATALOG")" | grep "$_ARCHIVENAME"
    if [[ $? != "0" ]]; then
      echo ERROR catalog --list for failed "\"$CATALOG\""
      TESTRESULT=1
    fi
done <  <(find "${TESTDIR}"/backups.d -type f -print0)


# check catalogs
echo "Check catalogs"
while IFS= read -r -d "" file
do
    CURRENT_BACKUPDEF=$(basename "$file")
    CATALOG="${CURRENT_BACKUPDEF}"${CATALOG_SUFFIX}
    echo "check catalog "\"$CATALOG\"
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
    echo "Test case succeeded"
else 
    echo "Test case FAILED"
fi

exit "$TESTRESULT"
