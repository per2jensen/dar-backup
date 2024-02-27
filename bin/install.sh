#! /bin/bash
#
#    Copyright (C) 2024  Per Jensen
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version


VERSION=@@DEV-VERSION@@

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
