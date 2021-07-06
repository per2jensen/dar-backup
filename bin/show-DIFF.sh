#! /bin/bash 


export DATE=`date -I`
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs


echo Mountpoint: ${MOUNT_POINT}
for archive in `ls ${MOUNT_POINT}/*_DIFF_*.dar|egrep "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u`; do
    BASE=`basename ${archive}`
    NO_SLICES=`find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l`
    printf "%-30s slices: %-5s\n" ${BASE} ${NO_SLICES}
done
