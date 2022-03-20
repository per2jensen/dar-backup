#! /bin/bash

# Test that the listFiles shows same number as files actually backed up

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/test-setup.sh

# run FULL backup
$TESTDIR/bin/dar-backup.sh -d TEST --local-backup-dir
failOnError $?

# alter files 
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"  # don't back this up

cp "$TESTDIR/dirs/include this one/Krummi.JPG" "$TESTDIR/dirs/include this one/Krummi.jpg" 
touch "$TESTDIR/dirs/include this one/Krummi-empty.JPG"

# run DIFF backup
$TESTDIR/bin/dar-diff-backup.sh -d TEST --local-backup-dir
failOnError $?

# alter files 
touch "$TESTDIR/dirs/include this one/GREENLAND.JPEG"
touch "$TESTDIR/dirs/exclude this one/GREENLAND.JPEG"  # don't back this up

cp "$TESTDIR/dirs/include this one/Krummi.JPG" "$TESTDIR/dirs/include this one/Krummi.MOV" 
touch "$TESTDIR/dirs/include this one/Krummi-empty2.JPG"
touch "$TESTDIR/dirs/include this one/Krummi-empty3.JPG"

# run listFiles
$TESTDIR/bin/dar-inc-backup.sh -d TEST --list-files --local-backup-dir
failOnError $?
NO_LISTED=$(cat /tmp/dar-INC-filelist.txt|grep -i "adding file"|wc -l)

if [[ $NO_LISTED != "4" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT

