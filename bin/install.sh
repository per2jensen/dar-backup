#! /bin/bash

# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version

_backup_file () {
  if [[ -f "$1" ]]; then
    cp "$1"  "${1}.org"
  fi
}

SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`

chmod +x ${SCRIPTDIRPATH}/*.sh ${SCRIPTDIRPATH}/../conf/*.duc 

mkdir "$SCRIPTDIRPATH"/../archives > /dev/null 2>&1


(cd "$SCRIPTDIRPATH"; rm dar-diff-backup.sh > /dev/null 2>&1; ln -s dar-backup.sh dar-diff-backup.sh) 
(cd "$SCRIPTDIRPATH"; rm dar-inc-backup.sh  > /dev/null 2>&1; ln -s dar-backup.sh dar-inc-backup.sh)

FILE="$SCRIPTDIRPATH/../conf/dar_par.dcf"
_backup_file "$FILE"
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/dar_par.dcf.template   > "$FILE"

FILE="$SCRIPTDIRPATH/../conf/defaults-rc"
_backup_file "$SCRIPTDIRPATH/../conf/defaults-rc"
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/darrc.template         > "$FILE"

sed --in-place=.org "s|@@ARCHIVE_DIR@@|${SCRIPTDIRPATH}/..|" $SCRIPTDIRPATH/../conf/dar-backup.conf 


if [ ! -d "$SCRIPTDIRPATH/../backups.d" ]; then
  mkdir "$SCRIPTDIRPATH/../backups.d"
fi
for file in $SCRIPTDIRPATH/../templates/backups.d/*; do
    base=`basename $file`
    sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" "$SCRIPTDIRPATH/../templates/backups.d/$base"  > "$SCRIPTDIRPATH/../backups.d/$base"
done
