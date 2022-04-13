#! /bin/bash

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# make sure mounts are in order
mountPrereqs

FILELIST="/tmp/dar-354Ay2534-filelist.txt"
echo Mountpoint: ${MOUNT_POINT}
for archive in $(ls ${MOUNT_POINT}/*.dar|grep -E "*_FULL_*|*_DIFF_*|*_INC_*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u); do
    BASE=$(basename ${archive})
    NO_SLICES=$(find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l)
    SLICE_SIZE=$(ls -l --block-size=G "${MOUNT_POINT}/${BASE}.1.dar"|cut -d" " -f5)
    dar -l  "$MOUNT_POINT/${BASE}" > "$FILELIST" 
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        SAVED_NO=$(grep -E -c "[Saved].*?] +-"  "$FILELIST")
        REMOVED_NO=$(grep -c " REMOVED ENTRY " "$FILELIST")        
    else 
        SAVED_NO="n/a"
        REMOVED_NO="n/a"
    fi
    rm ${FILELIST}
    DISK_USAGE_TOTAL=$(du -sch ${MOUNT_POINT}/${BASE}.*|grep -E "total"|cut -f1)
    printf "%-30s slices: %-3s (%s) total: %-6s Saved: %-7s Removed: %-7s \n" ${BASE} ${NO_SLICES} ${SLICE_SIZE} ${DISK_USAGE_TOTAL} ${SAVED_NO} ${REMOVED_NO}
done
DISK_USAGE_TOTAL=$(du -sch ${MOUNT_POINT}|grep -E "total"|cut -f1)
printf "Total disk usage in %s %s \n " ${MOUNT_POINT} ${DISK_USAGE_TOTAL}