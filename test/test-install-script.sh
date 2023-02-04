#! /bin/bash -x

#
# cp ~/git/dar-backup to /tmp, run install process, execute install backup definition
#

RESULT=0

TESTDIR=/tmp/dar-backup

rm -fr "$TESTDIR"
cp -R ~/git/dar-backup /tmp/
cd "$TESTDIR"

rm -fr "$TESTDIR"/.git
rm -fr "$TESTDIR"/.github
rm -fr "$TESTDIR"/test

chmod +x "$TESTDIR/bin/install.sh"
"$TESTDIR/bin/install.sh"

# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  echo ERROR catalog was not created, exiting
  exit 1
fi


find "$TESTDIR" -ls

"${TESTDIR}/bin/dar-backup.sh" -d dar-backup --local-backup-dir
if [[ $? != "0" ]]; then
    RESULT=1
fi

echo "RESULT: $RESULT"
exit "$RESULT"
