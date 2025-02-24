#! /bin/bash

#  - run mk-release.sh by patching it to accept a DEV tag
#  - unpack the tar file and run the installer
#  - run dar-backup (full, diff and inc)

if [[ -n "$1" ]]; then
    LATEST_DEV="$1"
    echo \$1:  "$1"
fi

TEST_RESULT=0

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
echo SCRIPTDIRPATH: "$SCRIPTDIRPATH"

#patch mk-release.sh
cp "$SCRIPTDIRPATH"/mk-release.sh /tmp/ || exit 1
sed -i 's/"\^v\\d+/"\^DEV\\d+/' /tmp/mk-release.sh
echo patched TAG regex in /tmp/mk-release.sh:
grep "TAG=" /tmp/mk-release.sh


# latest DEV tag
if [[ "$LATEST_DEV" == "" ]]; then 
    LATEST_DEV=$(git tag|grep -P  "DEV\d.\d"|sort|tail -n1)
fi
echo LATEST_DEV:  "$LATEST_DEV"
# build a "release" based on latest DEV tag
/tmp/mk-release.sh "$LATEST_DEV"  ||  { echo a release tar ball was not produced, exiting; exit 1; }


UNTAR_LOCATION=/tmp/dar-test-install/ 
TAR_FILE=dar-backup-linux-${LATEST_DEV}.tar.gz
echo TAR_FILE to test install of: "$TAR_FILE"
rm -fr "$UNTAR_LOCATION" || exit 1
# follow install instructions
mkdir -p "$UNTAR_LOCATION"
tar zxf "/tmp/${TAR_FILE}" --directory "$UNTAR_LOCATION"
chmod +x "$UNTAR_LOCATION"/dar-backup/bin/install.sh
"$UNTAR_LOCATION"/dar-backup/bin/install.sh
"$UNTAR_LOCATION"/dar-backup/bin/dar-backup.sh --local-backup-dir
TEST_RESULT=$?

touch "$UNTAR_LOCATION"/dar-backup/bin/DUMMY
"$UNTAR_LOCATION"/dar-backup/bin/dar-diff-backup.sh --local-backup-dir
RESULT=$?
if [[ "$RESULT"  != "0" ]]; then
  TEST_RESULT="$RESULT"
fi


touch "$UNTAR_LOCATION"/dar-backup/bin/DUMMY2
"$UNTAR_LOCATION"/dar-backup/bin/dar-inc-backup.sh --local-backup-dir
RESULT=$?
if [[ "$RESULT"  != "0" ]]; then
  TEST_RESULT="$RESULT"
fi

#cleanup
rm -fr "$UNTAR_LOCATION"  || exit 1
rm -f /tmp/"$TAR_FILE" || exit 1

echo TEST_RESULT: $TEST_RESULT
exit $TEST_RESULT
