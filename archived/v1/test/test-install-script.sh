#! /bin/bash 

#
# cp ~/git/dar-backup to /tmp, run install process, execute install backup definition
#


SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
source "$SCRIPTDIRPATH/../bin/dar-util.sh"

RESULT=0

INSTALLTEST=/tmp/installtest
TESTDIR="$INSTALLTEST"/dar-backup

rm -fr "$TESTDIR"
mkdir "$INSTALLTEST"

cp -R ~/git/dar-backup "$INSTALLTEST"

cd "$TESTDIR"

rm -fr "$TESTDIR"/.git
rm -fr "$TESTDIR"/.github
rm -fr "$TESTDIR"/test

chmod +x "$TESTDIR/bin/install.sh"
"$TESTDIR/bin/install.sh"

# create catalogs
"$TESTDIR/bin/manager.sh" --create-catalog --local-backup-dir
if [[ $? != "0" ]]; then
  log_error "catalog was not created, exiting"
  exit 1
fi

find "$TESTDIR" -ls

"${TESTDIR}/bin/dar-backup.sh" -d dar-backup --local-backup-dir
if [[ $? != "0" ]]; then
    RESULT=1
fi

if [[ "$RESULT" == "0" ]]; then
  log_success "$0"
else
  log_fail "$0"
fi

exit "$RESULT"
