#! /bin/bash

# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version

_backup_file () {
  if [[ -f "$1" ]]; then
    cp "$1"  "${1}.org"
  fi
}

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

ARCHIVE_DIR=$(realpath "$SCRIPTDIRPATH/../archives")
mkdir "$ARCHIVE_DIR" > /dev/null 2>&1

chmod +x "$SCRIPTDIRPATH"/*.sh

(cd "$SCRIPTDIRPATH"; rm dar-diff-backup.sh > /dev/null 2>&1; ln -s dar-backup.sh dar-diff-backup.sh) 
(cd "$SCRIPTDIRPATH"; rm dar-inc-backup.sh  > /dev/null 2>&1; ln -s dar-backup.sh dar-inc-backup.sh)


#template files
FILE="$SCRIPTDIRPATH/../conf/defaults-rc"
_backup_file "$FILE"
sed -e "s|@@CONFDIR@@|$(realpath "${SCRIPTDIRPATH}"/../conf)|" "$SCRIPTDIRPATH/../templates/darrc.template" > "$FILE"

FILE="$SCRIPTDIRPATH/../conf/dar-backup.conf"
_backup_file "$FILE"
sed -e "s|@@ARCHIVE_DIR@@|$(realpath "${SCRIPTDIRPATH}"/..)|" "$SCRIPTDIRPATH/../templates/dar-backup.conf.template" > "$FILE"        


if [ ! -d "$SCRIPTDIRPATH/../backups.d" ]; then
  mkdir "$SCRIPTDIRPATH/../backups.d"
fi
for file in "$SCRIPTDIRPATH"/../templates/backups.d/*; do
    base=$(basename "$file")
    sed -e "s|@@CONFDIR@@|$(realpath "${SCRIPTDIRPATH}"/../conf)|" "$SCRIPTDIRPATH/../templates/backups.d/$base"  > "$SCRIPTDIRPATH/../backups.d/$base"
done

for file in "$SCRIPTDIRPATH"/../templates/systemd/*; do
    base=$(basename "$file")
    sed -e "s|@@DAR_BACKUP_DIR@@|$(realpath "${SCRIPTDIRPATH}"/..)|" "$SCRIPTDIRPATH/../templates/systemd/$base"  > "$SCRIPTDIRPATH/../share/$base"
done
