#! /bin/bash
#
# Make a release tar file
#
# $1 is the tag to package

if [ -z "${1}" ]; then echo "tag not given, exiting"; exit 1; fi
echo tag to create release from: \""$1"\"

TAG=$(grep -P -o "^v\d+\.\d+\.\d+$" <<< "$1")
if [[ "$TAG" == "" ]]; then
    echo "TAG \"$1\" does not match required tag patten, exiting"
    exit 1
fi
if ! git show-ref --tags --quiet "$1"; then
 echo "TAG \"$1\" not found, exiting"
 exit 1
fi

DIR=/tmp/dar-backup
TARFILE="dar-backup-linux-${1}.tar.gz"

if [[ -e "$DIR" ]]; then rm -fr "$DIR" || exit 1; fi
if [[ -f "/tmp/$TARFILE" ]]; then rm "/tmp/$TARFILE" || exit 1; fi

cd /tmp || exit 1
git clone https://github.com/per2jensen/dar-backup.git || exit 1
cd dar-backup || exit 1

git  checkout "tags/$1" -b "release-$1" || exit 1
chmod +x bin/install.sh
rm -fr "$DIR/.git"
rm -fr "$DIR/.github"
rm -fr "$DIR/test"

echo "This package is built from tag: $1" > VERSION

# add version number to shell scripts
while IFS= read -r -d "" file
do
    sed -i "s/@@DEV-VERSION@@/$1/" "$file"
done <  <(find . -name "*.sh" -type f -print0)


cd $DIR/.. || exit 1
tar czvf "$TARFILE" dar-backup

rm -fr /tmp/dar-backup  || exit 1
tar -x -f ${TARFILE}  dar-backup/LICENSE  || exit 1
SHA256=$(sha256sum /tmp/dar-backup/LICENSE |cut -d" " -f1)
if  [[ "$SHA256" ==  "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986" ]]; then
    echo LICENSE exists in tarball and is unchanged
else
    echo "\"LICENSE\" file has changed, exiting"
    exit
fi

echo SHA256:
sha256sum "$TARFILE"
echo "SUCCESS: a release tarball from tag: \"$TAG\" was produced"
