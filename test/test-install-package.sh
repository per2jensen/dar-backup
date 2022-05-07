#! /bin/bash -x

#
# Build tar file from latest tag, run install process, execute install backup definition
#
_DIR=$(pwd)
# check if this is running in a Github Action
if [[ -d "/home/runner/work/dar-backup/dar-backup" ]]; then
    cd "/home/runner/work/dar-backup/dar-backup"
    git tag --list "v*"
    export TAG=$(git tag --list "v*"|sort -V|tail -n 1)
    cd "$_DIR"
fi
export RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")


"$SCRIPTDIRPATH"/mk-release.sh "$TAG"
find /tmp -name "dar-backup-linux*.gz" -ls 2> /dev/null


# cleanup before unpacking tar file
rm -fr /tmp/dar-backup || exit 1

# Follow install steps given in README.md
tar zxf /tmp/dar-backup-linux-"${TAG}".tar.gz --directory /tmp
chmod +x /tmp/dar-backup/bin/install.sh
/tmp/dar-backup/bin/install.sh
find /tmp/dar-backup -ls
/tmp/dar-backup/bin/dar-backup.sh --local-backup-dir --debug
if [[ $? != "0" ]]; then
    echo "ERROR delivered backup definition failed"
    RESULT=1
fi
find /tmp/dar-backup -ls
cat /tmp/dar-backup/archives/dar-backup.log

echo "non directories restored:"
find /tmp/dar-restore/ ! -type d

echo "RESULT: $RESULT"
exit "$RESULT"
