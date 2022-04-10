#! /bin/bash -x

#
# Build tar file, run install process, execute install backup definition
#

export TAG="DEV_install_package_dont_use"
export RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")


git push origin --delete "$TAG" > /dev/null 2>&1
# add tag
git tag -a -f  -m "unit test of installer" "$TAG"
git push --tags

"$SCRIPTDIRPATH"/mk-release.sh "$TAG"
find /tmp -name "dar-backup-linux*.gz" -ls 2> /dev/null

# remove tag
git push origin --delete "$TAG" > /dev/null 2>&1

rm -fr /tmp/dar-backup

# Follow install steps given in README.md
tar zxf /tmp/dar-backup-linux-"${TAG}".tar.gz --directory /tmp

# debug
find /tmp/dar-backup -ls

chmod +x /tmp/dar-backup/bin/install.sh
/tmp/dar-backup/bin/install.sh

/tmp/dar-backup/bin/dar-backup.sh --local-backup-dir
if [[ $? != "0" ]]; then
    echo "ERROR delivered backup definition failed"
    RESULT=1
fi
echo "The archive and log file should be here somewhere....."
find /tmp/dar-backup -ls

cat /tmp/dar-backup/archives/dar-backup.log

echo "The restored file should be here somewhere....."
find /tmp/dar-restore/ -ls

echo "RESULT: $RESULT"
exit "$RESULT"
