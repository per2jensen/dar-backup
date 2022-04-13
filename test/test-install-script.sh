#! /bin/bash -x

#
# Build tar file, run install process, execute install backup definition
#

export TAG="DEV_install_package_dont_use"
export RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

git tag --delete "$TAG"
if [[ $? != "0" ]]; then
    RESULT=1
fi
# add tag
git tag -a -f  -m "unit test of installer" "$TAG"
if [[ $? != "0" ]]; then
    RESULT=1
fi

DIR=/tmp/dar-backup

rm -fr "$DIR"
cd /tmp
git clone ~/git/dar-backup
cd dar-backup
git  checkout "tags/$TAG" -b "release-$TAG"

rm -fr "$DIR/.git"
rm -fr "$DIR/.github"
rm -fr "$DIR/test"

find "$DIR" -ls

chmod +x bin/install.sh
bin/install.sh

"$DIR/bin/dar-backup.sh -d dar-backup --local-backup-dir"
if [[ $? != "0" ]]; then
    RESULT=1
fi

echo "RESULT: $RESULT"
exit "$RESULT"
