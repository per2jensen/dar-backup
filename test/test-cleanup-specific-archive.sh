#! /bin/bash

# verify cleanup.sh cleans up a specific archive - given the --cleanup-archive option

TEST_RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

DAY_1_OLD=$(date --date="-1 days" -I)

touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.1.dar
touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.1.dar.vol000+100.par2
touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.2.dar
touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.2.dar.vol000+100.par2

touch "$TESTDIR"/archives/TEST_INC_${DAY_1_OLD}.1.dar
touch "$TESTDIR"/archives/TEST_INC_${DAY_1_OLD}.2.dar

# copy to alternate dir
cp -R "$TESTDIR"/archives "$TESTDIR"/archives2

# test 1
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-archive TEST_DIFF_${DAY_1_OLD}
COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "4" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi

COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "0" ]]; then
  echo there must not be INC cleanups
  TEST_RESULT=1
fi

# test 2
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-archive "TEST_INC_${DAY_1_OLD}"
COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "2" ]]; then
  echo number of INC cleanups is wrong
  TEST_RESULT=1
fi

# test3 check alternate-archive-dir also works
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"  --cleanup-archive "TEST_DIFF_${DAY_1_OLD}"
COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "8" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi

echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT
