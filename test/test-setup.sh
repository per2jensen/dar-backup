# test setup for every test script
# this is sourced in the actual test scripts

DATE=`date +"%Y-%m-%d"`
DRY_RUN=""
TESTRESULT=0

TESTDIR=/tmp/dar-backup-test

# Get the options
while [[ $# -gt 0 ]]; do
  case "$1" in
      --dry-run) DRY_RUN="--dry-run"; echo DRY_RUN enabled ;;
  esac
  shift
done


failOnError () {
  if [[ $1 != "0"  ]]; then
      echo operation failed, exiting
      exit 1
  fi
}


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
mkdir -p $TESTDIR/archives

cp -R $SCRIPTDIRPATH/dirs         $TESTDIR/
cp -R $SCRIPTDIRPATH/../bin       $TESTDIR/
cp -R $SCRIPTDIRPATH/../conf      $TESTDIR/
# override some conf files with test versions
cp -R $SCRIPTDIRPATH/conf         $TESTDIR/


# create templates dir and copy it
cp -R $SCRIPTDIRPATH/templates    $TESTDIR/
cp $SCRIPTDIRPATH/../templates/dar_par.dcf.template $TESTDIR/templates/
cp $SCRIPTDIRPATH/../templates/darrc.template       $TESTDIR/templates/

# install and run FULL backup
chmod +x $TESTDIR/bin/install.sh
$TESTDIR/bin/install.sh

source $TESTDIR/conf/dar-backup.conf
