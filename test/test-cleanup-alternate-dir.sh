#! /bin/bash

# verify cleanup.sh works on the directory given in the --alternate-archive-dir option
# that option requires --local-backup-dir to be given also

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

# run backups, so there is something to cleanup
$SCRIPTDIRPATH/test-backups.sh

cp -R "$TESTDIR"/archives "$TESTDIR"/archives2


# set DIFF_AGE and INC_AGE so that INCs are cleaned up
sed -i s/INC_AGE.*/INC_AGE=-1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/DIFF_AGE.*/DIFF_AGE=0/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"

COUNT=$(grep -c "clean up:" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "3" ]]; then
  echo number of INC cleanups is wrong
  exit 1
fi

COUNT=$(grep -c -E "clean up: .*?DIFF" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "0" ]]; then
  echo a DIFF archive was found, should only have been INCs
  exit 1
fi


# set DIFF_AGE and INC_AGE so that DIFFs are cleaned up
sed -i s/DIFF_AGE.*/DIFF_AGE=-1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/INC_AGE.*/INC_AGE=0/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"

COUNT=$(grep -c -E "clean up: .*?DIFF" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "3" ]]; then
  echo total number of DIFFs deleted expected to be 3
  exit 1
fi

# check no FULLs has been cleaned up
COUNT=$(grep -c -E "clean up: .*?FULL" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "0" ]]; then
  echo one or more FULL archives were cleaned up
  exit 1
fi


#verify all archives still exists in $TESTDIR/archives and only FULL's in $TESTDIR/archives2
COUNT=$(ls /tmp/dar-backup-test/archives|grep -c -E "FULL|DIFF|INC")
echo "COUNT: $COUNT"
if [[ "$COUNT" != "9" ]]; then
  echo one or more archives were cleaned up in $TESTDIR/archives
  exit 1
fi


COUNT=$(ls /tmp/dar-backup-test/archives2|grep -c -E "FULL")
echo "COUNT: $COUNT"
if [[ "$COUNT" != "3" ]]; then
  echo there must be 3 FULL archive files in $TESTDIR/archives2
  exit 1
fi

COUNT=$(ls /tmp/dar-backup-test/archives2|grep -c -E "DIFF|INC")
echo "COUNT: $COUNT"
if [[ "$COUNT" != "0" ]]; then
  echo there is one or more DIFF or INC archive files in $TESTDIR/archives2
  exit 1
fi



