#! /bin/bash

# verify cleanup.sh works on the directory given in the --alternate-archive-dir option
# that option requires --local-backup-dir


TEST_RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

DAY_1_OLD=$(date --date="-1 days" -I)
DAY_2_OLD=$(date --date="-2 days" -I)

touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.dar
touch "$TESTDIR"/archives/TEST_DIFF_${DAY_2_OLD}.dar

touch "$TESTDIR"/archives/TEST_INC_${DAY_1_OLD}.dar
touch "$TESTDIR"/archives/TEST_INC_${DAY_2_OLD}.dar

cp -R "$TESTDIR"/archives "$TESTDIR"/archives2

# set DIFF_AGE and INC_AGE so that one DIFF and one INC are cleaned up
sed -i s/INC_AGE.*/INC_AGE=2/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/DIFF_AGE.*/DIFF_AGE=2/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"

COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "1" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi

COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "1" ]]; then
  echo number of INC cleanups is wrong
  TEST_RESULT=1
fi

# set DIFF_AGE and INC_AGE so that one more DIFF and one more INC are cleaned up
sed -i s/DIFF_AGE.*/DIFF_AGE=1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/INC_AGE.*/INC_AGE=1/   "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"

COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "2" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi

COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "2" ]]; then
  echo number of INC cleanups is wrong
  TEST_RESULT=1
fi

if [[ "$TEST_RESULT" == "0" ]]; then
  echo "test of cleanup successfully completed"
fi

#verify all archives still exists in $TESTDIR/archives
COUNT=$(ls /tmp/dar-backup-test/archives|grep -c -E "FULL|DIFF|INC")
echo "COUNT: $COUNT"
if [[ "$COUNT" != "4" ]]; then
  echo one or more archives were cleaned up in $TESTDIR/archives
  TEST_RESULT=1
fi

echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT

