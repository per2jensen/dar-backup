#! /bin/bash

#
# Build tar file, run install process, execute install backup definition
#

export TAG="DEV_install_package_dont_use"
export RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

git push origin --delete "$TAG" > /dev/null 2>&1
git tag -a -f  -m "unit test of installer" "$TAG"
git push --tags

"$SCRIPTDIRPATH"/mk-release.sh "$TAG"

rm -fr /tmp/dar-backup

# Follow install steps given in README.md
tar zxf /tmp/dar-backup-linux-"${TAG}".tar.gz --directory /tmp
chmod +x /tmp/dar-backup/bin/install.sh
/tmp/dar-backup/bin/install.sh
/tmp/dar-backup/bin/dar-backup.sh --local-backup-dir
if [[ $? != "0" ]]; then
    echo "ERROR delivered backup definition failed, exiting"
    RESULT=1
fi
cat /tmp/dar-backup/archives/dar-backup.log

echo "RESULT: $RESULT"
exit "$RESULT"
