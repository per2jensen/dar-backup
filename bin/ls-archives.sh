#! /bin/bash 

export DATE=`date -I`
export SCRIPTPATH=`realpath "$0"`
export SCRIPTDIRPATH=`dirname "$SCRIPTPATH"`

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs

echo Mountpoint: ${MOUNT_POINT}
for archive in `ls ${MOUNT_POINT}/*.dar|egrep "*_FULL_*|*_DIFF_*|*_INC_*"|egrep "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u`; do
    BASE=`basename ${archive}`
    NO_SLICES=`find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l`
    SLICE_SIZE=`ls -l --block-size=G "${MOUNT_POINT}/${BASE}.1.dar"|cut -d" " -f5`
    DISK_USAGE_TOTAL=`du -sch ${MOUNT_POINT}/${BASE}.*|egrep "total"|cut -f1`
    printf "%-30s slices: %-3s (%s)   total: %-10s  \n" ${BASE} ${NO_SLICES} ${SLICE_SIZE} ${DISK_USAGE_TOTAL}
done
DISK_USAGE_TOTAL=`du -sch ${MOUNT_POINT}|egrep "total"|cut -f1`
printf "Total disk usage in %s: %s \n" ${MOUNT_POINT} ${DISK_USAGE_TOTAL}