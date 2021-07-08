#! /bin/bash 
# print FULL archives including  number of slices and the slice size

export DATE=`date -I`
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs


echo Mountpoint: ${MOUNT_POINT}
for archive in `ls ${MOUNT_POINT}/*_FULL_*.dar|egrep "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u`; do
    BASE=`basename ${archive}`
    NO_SLICES=`find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l`
    SLICE_SIZE=`ls -l --block-size=G "${MOUNT_POINT}/${BASE}.1.dar"|cut -d" " -f5`
    printf "%-30s slices: %-3s (%s)\n" ${BASE} ${NO_SLICES} ${SLICE_SIZE}
done
