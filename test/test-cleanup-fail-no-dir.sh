#! /bin/bash

# test cleanup.sh fails if the alternate-archive-dir does not exist

TEST_RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

source "$SCRIPTDIRPATH/setup.sh"
source "$TESTDIR/conf/dar-backup.conf"

"$TESTDIR"/bin/cleanup.sh --local-backup-dir  --alternate-archive-dir /dir/does/not/exist
RESULT=$?

if [[ "$RESULT" != "1"  ]]; then
    TEST_RESULT=1
fi

grep ERROR "$TESTDIR"/archives/dar-backup.log > /dev/null
RESULT=$?

if [[ "$RESULT" != "0"  ]]; then
    TEST_RESULT=1
fi

echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT
