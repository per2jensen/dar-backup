#! /bin/bash -x

#
# Do install from HEAD, run install process, execute install backup definition
#
SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
RESULT=0

# cleanup before starting 
DIR=/tmp/dar-backup
if [[ -e "$DIR" ]]; then rm -fr "$DIR" || exit 1; fi

# Follow install steps given in README.md
cd /tmp || exit 1
git clone https://github.com/per2jensen/dar-backup.git || exit 1
chmod +x /tmp/dar-backup/bin/install.sh || exit 1
/tmp/dar-backup/bin/install.sh || exit 1
/tmp/dar-backup/bin/dar-backup.sh --local-backup-dir --debug
if [[ $? != "0" ]]; then
    echo "ERROR delivered backup definition failed"
    RESULT=1
fi
find /tmp/dar-backup  -name ".git*" -prune  -o -ls
cat /tmp/dar-backup/archives/dar-backup.log

echo "non directories restored:"
find /tmp/dar-restore/ ! -type d

echo "RESULT: $RESULT"
exit "$RESULT"
