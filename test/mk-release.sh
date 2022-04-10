#! /bin/bash
#
# Make a release tar file
#
# $1 is the tag to package

if [ -z "${1}" ]; then echo "tag not given, exiting"; exit; fi
echo tag to create release from: "$1"

DIR=/tmp/dar-backup
TARFILE="dar-backup-linux-${1}.tar.gz"

rm -fr "$DIR"
cd /tmp
git clone https://github.com/per2jensen/dar-backup.git
cd dar-backup
git  checkout "tags/$1" -b "release-$1"
chmod +x bin/install.sh
rm -fr "$DIR/.git"
rm -fr "$DIR/.github"
rm -fr "$DIR/test"
echo "This package is built from tag: $1" > VERSION
cd $DIR/..
tar czvf "$TARFILE" dar-backup
echo SHA256:
sha256sum "$TARFILE"
