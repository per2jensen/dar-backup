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
echo "test 1"
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive TEST_DIFF_${DAY_1_OLD}
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
echo "test 2"
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_INC_${DAY_1_OLD}"
COUNT=$(grep -c -E "clean up:.*_INC_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "2" ]]; then
  echo number of INC cleanups is wrong
  TEST_RESULT=1
fi

# test3 check alternate-archive-dir also works
echo "test 3"
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "$TESTDIR/archives2"  --cleanup-specific-archive "TEST_DIFF_${DAY_1_OLD}"
COUNT=$(grep -c -E "clean up:.*_DIFF_" "$TESTDIR"/archives/dar-backup.log)
echo "COUNT: $COUNT"
if [[ "$COUNT" != "8" ]]; then
  echo number of DIFF cleanups is wrong
  TEST_RESULT=1
fi


#test 4 fail on date
echo "test 4"
TEST_DATE=2022-13-01
touch "$TESTDIR"/archives/TEST_DIFF_${TEST_DATE}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_DIFF_${TEST_DATE}"
if [[ $? != "1" ]]; then 
  echo test 4 fails
  TEST_RESULT=1
fi

# test 5 fail on date
echo "test 5"
TEST_DATE=2023-04-32
touch "$TESTDIR"/archives/TEST_DIFF_${TEST_DATE}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_DIFF_${TEST_DATE}"
if [[ $? != "1" ]]; then 
  echo test 5 fails
  TEST_RESULT=1
fi

# test 6 fail on date
echo "test 6"
TEST_DATE=2019-12-31
touch "$TESTDIR"/archives/TEST_DIFF_${TEST_DATE}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_DIFF_${TEST_DATE}"
if [[ $? != "1" ]]; then 
  echo test 6 fails
  TEST_RESULT=1
fi

# test 7 fail on date
echo "test 7"
TEST_DATE=2022-011-01
touch "$TESTDIR"/archives/TEST_DIFF_${TEST_DATE}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_DIFF_${TEST_DATE}"
if [[ $? != "1" ]]; then 
  echo test 7 fails
  TEST_RESULT=1
fi

# test 8 fail on date
echo "test 8"
TEST_DATE=2022-01-1
touch "$TESTDIR"/archives/TEST_DIFF_${TEST_DATE}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_DIFF_${TEST_DATE}"
if [[ $? != "1" ]]; then 
  echo test 8 fails
  TEST_RESULT=1
fi

#test 9
# verify "*" is not allowed
echo "test 9"
("$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "TEST_*_${TEST_DATE}")
if [[ $? != "1" ]]; then 
  echo test 9 fails
  TEST_RESULT=1
fi

#test 10
# verify "*" is not allowed
echo "test 10"
("$TESTDIR"/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "/tmp/*/TEST")
if [[ $? != "1" ]]; then 
  echo test 10 fails
  TEST_RESULT=1
fi


#test 11
# verify path is stripped 
echo "test 11"
touch "$TESTDIR"/archives/TEST_DIFF_${DAY_1_OLD}.1.dar
"$TESTDIR"/bin/cleanup.sh --local-backup-dir --cleanup-specific-archive "/some/path/TEST_INC_${DAY_1_OLD}"
if [[ $? != "0" ]]; then 
  echo test 11 fails
  TEST_RESULT=1
fi



echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT
