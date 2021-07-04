#! /bin/bash 

# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version


SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`

chmod +x ${SCRIPTDIRPATH}/dar-backup.sh ${SCRIPTDIRPATH}/../conf/*.duc 

(cd "$SCRIPTDIRPATH"; rm dar-diff-backup.sh; ln -s dar-backup.sh  dar-diff-backup.sh) 

sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/dar_par.dcf.template   > $SCRIPTDIRPATH/../conf/dar_par.dcf
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/darrc.template         > $SCRIPTDIRPATH/../conf/defaults-rc
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../templates/TEST                   > $SCRIPTDIRPATH/../backups.d/TEST
