#! /bin/bash 
# Run script as a non-root user 
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"


export DATE=`date -I`
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs


for archive in `ls ${MOUNT_POINT}/*_DIFF_*|egrep "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u`; do
    BASE=`basename ${archive}`
    NO_SLICES=`find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l`
    echo ${archive}: Number of slices: ${NO_SLICES} 
done
