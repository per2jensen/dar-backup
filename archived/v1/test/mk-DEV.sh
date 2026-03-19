#! /bin/bash
#
# package scripts into a tar and set the DEV-version
#
# $1 is the DEV-tag to package

if [ -z "${1}" ]; then echo "tag not given, exiting"; exit; fi
echo tag to create release from: \""$1"\"

TAG=$(grep -P -o "^DEV\d+\.\d+\.\d+$" <<< "$1")
if [[ "$TAG" == "" ]]; then
    echo "TAG \"$1\" does not match required DEV tag patten, exiting"
    exit 1
fi
if ! git show-ref --tags --quiet "$1"; then
 echo "TAG \"$1\" not found, exiting"
 exit 1
fi

DIR=/tmp/dar-backup
TARFILE="dar-backup-scripts-${1}.tar.gz"

if [[ -e "$DIR" ]]; then rm -fr "$DIR" || exit 1; fi
if [[ -f "/tmp/$TARFILE" ]]; then rm "/tmp/$TARFILE" || exit 1; fi

cd /tmp || exit 1
git clone https://github.com/per2jensen/dar-backup.git || exit 1
cd dar-backup || exit 1

git  checkout "tags/$1" -b "release-$1" || exit 1
chmod +x bin/*.sh

# add version number to shell scripts
while IFS= read -r -d "" file
do
    sed -i "s/@@DEV-VERSION@@/$1/" "$file"
done <  <(find . -name "*.sh" -type f -print0)


cd $DIR/.. || exit 1
tar czvf "$TARFILE" dar-backup/bin


echo "Unpack command into Per's dar-backup directory:"
echo "==>  tar xvf /tmp/$TARFILE --directory ~/programmer/"
