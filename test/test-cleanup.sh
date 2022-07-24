#! /bin/bash

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# run dar-diff-backup.sh
# cleanup DIFF and INC archives

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

#check that a direcotry name does not mess anythin up (it did on a usbdisk  disk :-) )
mkdir "$TESTDIR"/archives/"$DAY_2_OLD"
touch "$TESTDIR"/archives/"$DAY_2_OLD"/TEST_DIFF_${DAY_2_OLD}.dar
touch "$TESTDIR"/archives/"$DAY_2_OLD"/TEST_INC_${DAY_2_OLD}.dar


# set DIFF_AGE and INC_AGE so that one DIFF and one INC are cleaned up
sed -i s/INC_AGE.*/INC_AGE=2/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/DIFF_AGE.*/DIFF_AGE=2/ "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir

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

# set DIFF_AGE and INC_AGE so that one more DIFF and one more INC are cleaned up
sed -i s/DIFF_AGE.*/DIFF_AGE=1/ "$TESTDIR"/conf/dar-backup.conf
sed -i s/INC_AGE.*/INC_AGE=1/   "$TESTDIR"/conf/dar-backup.conf

"$TESTDIR"/bin/cleanup.sh --local-backup-dir

COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "3" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi

COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "3" ]]; then
  echo number of INC cleanups is wrong
  TEST_RESULT=1
fi

echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT
