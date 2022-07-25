#! /bin/bash
#
# Make a release tar file
#
# $1 is the tag to package

if [ -z "${1}" ]; then echo "tag not given, exiting"; exit; fi
echo tag to create release from: \""$1"\"

TAG=$(grep -P -o "^v\d+\.\d+\.\d+$" <<< "$1")
if [[ "$TAG" == "" ]]; then
    echo "TAG \"$1\" does not match required tag patten, exiting"
    exit 1
fi

DIR=/tmp/dar-backup
TARFILE="dar-backup-linux-${1}.tar.gz"

if [[ -e "$DIR" ]]; then rm -fr "$DIR" || exit 1; fi
if [[ -f "/tmp/$TARFILE" ]]; then rm "/tmp/$TARFILE" || exit 1; fi

cd /tmp || exit 1
git clone https://github.com/per2jensen/dar-backup.git || exit 1
cd dar-backup || exit 1

git  checkout "tags/$1" -b "release-$1" || exit 1
chmod +x bin/install.sh
rm -fr "$DIR/.git"
rm -fr "$DIR/.github"
rm -fr "$DIR/test"

echo "This package is built from tag: $1" > VERSION
sed -i "s/@@DEV-VERSION@@/$1/" bin/dar-backup.sh
cd $DIR/.. || exit 1
tar czvf "$TARFILE" dar-backup
echo SHA256:
sha256sum "$TARFILE"

echo "SUCCESS: a release tarball from tag: \"$TAG\" was produced"
