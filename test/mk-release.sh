#! /bin/bash
#
# Make a release tar file
#
# $1 is the tag to package

if [ -z ${1} ]; then echo "tag not given, exiting"; exit; fi
echo tag to create release from: $1

DIR=/tmp/dar-backup

rm -fr $DIR
cd /tmp
git clone https://github.com/per2jensen/dar-backup.git
cd dar-backup
git  checkout "tags/$1" -b release-$1
chmod +x bin/install.sh
rm -fr $DIR/.git
rm -fr $DIR/.github
cp $DIR/test/conf/dar-backup.conf.release $DIR/conf/dar-backup.conf
rm -fr $DIR/test
echo "This package is built from tag: $1" > VERSION
cd $DIR/..
TARFILE=dar-backup-linux-${1}.tar.gz
tar czvf $TARFILE dar-backup
echo SHA256:
sha256sum $TARFILE
