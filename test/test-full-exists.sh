#! /bin/bash

# Run diff without a full, expect an exit code = 100

SCRIPTPATH=`realpath $0`


SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH
DATE=`date +"%Y-%m-%d"`
DRY_RUN=""
TESTRESULT=0

TESTDIR=/tmp/dar-backup-test
TEST_ARCHIVE_DIR=/tmp/dar-backup-archives
echo $0


# Get the options
while [[ $# -gt 0 ]]; do
  case "$1" in
      --dry-run) DRY_RUN="--dry-run" ;;
  esac
  shift
done

# grep for expected string and print result
# $1: search string
# $2: logfile to search in
checkExpectLog () {
  grep -P "$1" "$2" > /dev/null
  if [[ $? == "0" ]]; then
    echo ok \"$1\" found
  else
    echo ERROR: \"$1\" NOT found
    TESTRESULT=1
  fi
}

# grep for string expected NOT to be found and print result
# $1: search string
# $2: logfile to search in
checkDontFindLog () {
  grep -P "$1" "$2" > /dev/null
  if [[ $? == "0" ]]; then
    echo ERROR \"$1\" was found
    TESTRESULT=1
  else
    echo ok \"$1\" not found as expected 
  fi
}


rm -fr $TESTDIR
rm -fr $TEST_ARCHIVE_DIR 
rm -fr ~/mnt/TEST/*
mkdir -p $TESTDIR
mkdir $TEST_ARCHIVE_DIR

cp -R $SCRIPTDIRPATH/dirs         $TESTDIR/
cp -R $SCRIPTDIRPATH/../bin       $TESTDIR/
cp -R $SCRIPTDIRPATH/../conf      $TESTDIR/
# override some conf files with test versions
cp -R $SCRIPTDIRPATH/conf         $TESTDIR/



source $TESTDIR/conf/dar-backup.conf

# create templates dir and copy it
cp -R $SCRIPTDIRPATH/templates    $TESTDIR/
cp $SCRIPTDIRPATH/../templates/dar_par.dcf.template $TESTDIR/templates/
cp $SCRIPTDIRPATH/../templates/darrc.template       $TESTDIR/templates/


# install
chmod +x $TESTDIR/bin/install.sh
$TESTDIR/bin/install.sh


# run DIFF backup
$TESTDIR/bin/dar-diff-backup.sh -d TEST $DRY_RUN --local-backup-dir
if [[ $? != "100" ]]; then
  echo DIFF backup did not fail as expected, due to no FULL backup found
  TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT
