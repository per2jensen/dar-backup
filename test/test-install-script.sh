#! /bin/bash -x

#
# cp ~/git/dar-backup to /tmp, run install process, execute install backup definition
#

RESULT=0

DIR=/tmp/dar-backup

rm -fr "$DIR"
cp -R ~/git/dar-backup /tmp/
cd "$DIR"

rm -fr "$DIR"/.git
rm -fr "$DIR"/.github
rm -fr "$DIR"/test

chmod +x "$DIR/bin/install.sh"
"$DIR/bin/install.sh"

find "$DIR" -ls

"${DIR}/bin/dar-backup.sh" -d dar-backup --local-backup-dir
if [[ $? != "0" ]]; then
    RESULT=1
fi

echo "RESULT: $RESULT"
exit "$RESULT"
