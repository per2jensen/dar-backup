#! /bin/bash

# check that ls-archives.sh -l works

SCRIPTPATH=$(realpath $0)
SCRIPTDIRPATH=$(dirname $SCRIPTPATH)
#echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/setup.sh

touch $TESTDIR/backups.d/TEST_BACKUP_DEF

# list definitions in backups.d/
DEFS=$($TESTDIR/bin/ls-archives.sh -l)
if [[ $? != "0" ]]; then
  echo ERROR list operation failed
  TESTRESULT=1
fi
echo $DEFS|grep -o TEST_BACKUP_DEF
if [[ $? != "0" ]]; then
  echo ERROR definition TEST_BACKUP_DEF not found
  TESTRESULT=1
fi


# check another option works
$TESTDIR/bin/ls-archives.sh -h  > /dev/null
if [[ $? != "0" ]]; then
  echo a non list option failed
  TESTRESULT=1
fi

#echo TEST RESULT: $TESTRESULT
exit $TESTRESULT
