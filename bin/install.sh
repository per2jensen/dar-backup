#! /bin/bash 

# set correct dir paths in config files
# make the backup executable
# create the softlink for the "diff" version


SCRIPTPATH=`realpath $0`
SCRIPTDIRPATH=`dirname $SCRIPTPATH`
echo $SCRIPTDIRPATH

chmod +x ${SCRIPTDIRPATH}/dar-backup.sh
ln -s ${SCRIPTDIRPATH}/dar-backup.sh  ${SCRIPTDIRPATH}/dar-diff-backup.sh 

sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../conf/dar_par.dcf.template > $SCRIPTDIRPATH/../conf/dar_par.dcf
sed -e "s|@@CONFDIR@@|${SCRIPTDIRPATH}/../conf|" $SCRIPTDIRPATH/../conf/darrc.template       > $SCRIPTDIRPATH/../conf/darrc

