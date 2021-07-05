#! /bin/bash -x

# run install.sh
# run dar-backup.sh
# add file GREENLAND.JEP to include dir and to the exclude dir
# run dar-diff-backup.sh
# list the FULL & DIFF archives

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
DATE=`date +"%Y-%m-%d"`

TESTDIR=/tmp/dar-backup-test

rm -fr $TESTDIR
rm -fr ~/mnt/TEST/*
mkdir -p $TESTDIR

cp -R $SCRIPTDIRPATH/dirs         $TESTDIR/
cp -R $SCRIPTDIRPATH/../bin       $TESTDIR/
cp -R $SCRIPTDIRPATH/../conf      $TESTDIR/

source $TESTDIR/conf/dar-backup.conf

# create templates dir and copy it
cp -R $SCRIPTDIRPATH/templates    $TESTDIR/
cp $SCRIPTDIRPATH/../templates/dar_par.dcf.template $TESTDIR/templates/
cp $SCRIPTDIRPATH/../templates/darrc.template       $TESTDIR/templates/


# install and run FULL backup
(cd $TESTDIR/bin; chmod +x install.sh  &&  $TESTDIR/bin/install.sh  &&  $TESTDIR/bin/dar-backup.sh)
dar -l  "$MOUNT_POINT/TEST_FULL_$DATE" > $TESTDIR/FULL-filelist.txt


# alter backup set
cp GREENLAND.JPEG "$TESTDIR/dirs/include this one/"
cp GREENLAND.JPEG "$TESTDIR/dirs/exclude this one/"

# run DIFF backup
(cd $TESTDIR/bin  &&  $TESTDIR/bin/dar-diff-backup.sh)
dar -l  "$MOUNT_POINT/TEST_DIFF_$DATE" > $TESTDIR/DIFF-filelist.txt


cat $TESTDIR/FULL-filelist.txt 
cat $TESTDIR/DIFF-filelist.txt
cat $TESTDIR/dar-backup.log
