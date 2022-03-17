#! /bin/bash

# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version


SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`

chmod +x ${SCRIPTDIRPATH}/*.sh ${SCRIPTDIRPATH}/../conf/*.duc 

(cd "$SCRIPTDIRPATH"; rm dar-diff-backup.sh > /dev/null 2>&1; ln -s dar-backup.sh dar-diff-backup.sh) 
(cd "$SCRIPTDIRPATH"; rm dar-inc-backup.sh  > /dev/null 2>&1; ln -s dar-backup.sh dar-inc-backup.sh)

sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/dar_par.dcf.template   > $SCRIPTDIRPATH/../conf/dar_par.dcf
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/darrc.template         > $SCRIPTDIRPATH/../conf/defaults-rc

if [ ! -d "$SCRIPTDIRPATH/../backups.d" ]; then
  mkdir "$SCRIPTDIRPATH/../backups.d"
fi
for file in $SCRIPTDIRPATH/../templates/backups.d/*; do
    base=`basename $file`
    sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" "$SCRIPTDIRPATH/../templates/backups.d/$base"  > "$SCRIPTDIRPATH/../backups.d/$base"
done
