#! /bin/bash

# Test that the listFiles shows same number as files actually backed up

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/setup.sh

# run FULL backup
$TESTDIR/bin/dar-backup.sh -d TEST --local-backup-dir
failOnError $?

# alter files 
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"  # don't back this up

cp "$TESTDIR/dirs/include this one/Krummi.JPG" "$TESTDIR/dirs/include this one/Krummi.jpg" 
touch "$TESTDIR/dirs/include this one/Krummi-empty.JPG"
touch "$TESTDIR/dirs/include this one/Krummi-empty2.JPG"
touch "$TESTDIR/dirs/include this one/Krummi-empty3.JPG"




# run listFiles
$TESTDIR/bin/dar-diff-backup.sh -d TEST --list-files --local-backup-dir
failOnError $?
NO_LISTED=$(cat /tmp/dar-DIFF-filelist.txt|grep -E -i "adding file|adding symlink"|wc -l)

if [[ $NO_LISTED != "5" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT

