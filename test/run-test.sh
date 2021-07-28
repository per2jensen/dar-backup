#! /bin/bash 

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# run dar-diff-backup.sh
# list the FULL & DIFF archives

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
    echo \"$1\" found
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
    echo \"$1\" not found, as expected
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


# install and run FULL backup
(cd $TESTDIR/bin; chmod +x install.sh  &&  $TESTDIR/bin/install.sh  &&  $TESTDIR/bin/dar-backup.sh $DRY_RUN --local-backup-dir)
dar -l  "$MOUNT_POINT/TEST_FULL_$DATE" > $TESTDIR/FULL-filelist.txt



# alter backup set
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"

# run DIFF backup
(cd $TESTDIR/bin  &&  $TESTDIR/bin/dar-diff-backup.sh $DRY_RUN --local-backup-dir)
dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > $TESTDIR/DIFF-filelist.txt


cat $TESTDIR/FULL-filelist.txt 
cat $TESTDIR/DIFF-filelist.txt
cat $TESTDIR/dar-backup.log
echo RESULTS:
# FULL backup
checkExpectLog   "\[Saved\].*?dirs/include this one/Abe.jpg"        "$TESTDIR/FULL-filelist.txt"
checkExpectLog   "\[Saved\].*?dirs/include this one/Krummi.JPG"     "$TESTDIR/FULL-filelist.txt"
checkExpectLog   "\[Saved\].*?dirs/compressable/Lorem Ipsum.txt"    "$TESTDIR/FULL-filelist.txt"
checkDontFindLog "include this one/GREENLAND.JPEG"                  "$TESTDIR/FULL-filelist.txt"
checkDontFindLog "exclude this one/In exclude dir.txt"              "$TESTDIR/FULL-filelist.txt"

# DIFF backup
checkExpectLog   "\[Saved\].*?dirs/include this one/GREENLAND.JPEG" "$TESTDIR/DIFF-filelist.txt"  
checkDontFindLog "exclude this one/GREENLAND.JPEG"                  "$TESTDIR/DIFF-filelist.txt"  

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT