#! /bin/bash

# Test that the listFiles shows same number as files actually backed up

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo SCRIPTDIRPATH: $SCRIPTDIRPATH

source $SCRIPTDIRPATH/test-setup.sh

# run FULL backup
$TESTDIR/bin/dar-backup.sh -d TEST --local-backup-dir

# alter files 
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp $SCRIPTDIRPATH/GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"  # don't back this up

cp "$TESTDIR/dirs/include this one/Krummi.JPG" "$TESTDIR/dirs/include this one/Krummi.jpg" 
touch "$TESTDIR/dirs/include this one/Krummi-empty.JPG"




# run listFiles
$TESTDIR/bin/dar-diff-backup.sh -d TEST --list-files --local-backup-dir
NO_LISTED=$(cat /tmp/dar-DIFF-filelist.txt|grep -i "adding file"|wc -l)


if [[ $NO_LISTED != "3" ]]; then
    TESTRESULT=1
fi

echo TEST RESULT: $TESTRESULT
exit $TESTRESULT

