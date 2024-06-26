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

SCRIPTPATH=$(realpath "$0")
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")
SCRIPTNAME=$(basename "$0")

VERSION=@@DEV-VERSION@@

LOCAL_BACKUP_DIR=""
ALTERNATE_ARCHIVE_DIR=""
BACKUPDEF=""
LISTDEF=""

# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --local-backup-dir)
          LOCAL_BACKUP_DIR=1
          ;;
      --alternate-archive-dir)
          shift
          ALTERNATE_ARCHIVE_DIR="$1"
          ;;
      --backupdef|-d)
          shift
          BACKUPDEF="$1"
          ;;
      --listdef|-l)
          LISTDEF="1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME [--help|-h] [--version|-v] [--backupdef|-d <backup definition>] [--listdef|-l][--local-backup-dir] [--alternate-archive-dir <directory>]"
          echo "   --backupdef <backup definition>, list only archives for this backup definition"
          echo "   --listdef, list backup definitions"
          echo "   --local-backup-dir, don't mount a remote directory for cleanup operations"
          echo "   --alternate-archive-dir <directory>, list another directory than the one configured, this probably requires --local-backup-dir also"
          echo "   --version, show version number and license"
          exit
          ;;
      --version|-v)
          echo "$SCRIPTNAME $VERSION"
          echo "Licensed under GNU GENERAL PUBLIC LICENSE v3, see \"LICENSE\" file for details"
          echo "THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW, see section 15 and section 16 in the \"LICENSE\" file"
          exit
          ;;
      *)
          echo option \"$1\" not recognized, exiting
          exit
          ;;
  esac
  shift
done


source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"
source "${SCRIPTDIRPATH}/dar-util.sh"

# list backup definitions and exit (--listdef or -l)
if [[ $LISTDEF == "1" ]]; then
  find $SCRIPTDIRPATH/../backups.d/ -type f -print
  exit 
fi

# set MOUNT_POINT to the alternate archive dir
# this (most probably) requires the --local-backup-dir option to be set also
if [[ $ALTERNATE_ARCHIVE_DIR != "" ]]; then
  if [[ ! -d "$ALTERNATE_ARCHIVE_DIR"  ]]; then
    log "ERROR alternate archive directory: \"$ALTERNATE_ARCHIVE_DIR\" not found, $SCRIPTNAME exiting"
    exit 1
  fi
  MOUNT_POINT="$ALTERNATE_ARCHIVE_DIR"
fi

# make sure mounts are in order
mountPrereqs

FILELIST="/tmp/dar-354Ay2534-filelist.txt"
echo Mountpoint: ${MOUNT_POINT}

SEARCHCRIT="*.dar"
if [[ $BACKUPDEF != "" ]]; then
    SEARCHCRIT="${BACKUPDEF}*.dar"
fi

for archive in $(find ${MOUNT_POINT} -name "$SEARCHCRIT"|grep -E ".*_FULL_.*|.*_DIFF_.*|.*_INC_.*"|grep -E "^.*?[0-9]{4}-[0-9]{2}-[0-9]{2}" -o|sort -u); do
    BASE=$(basename ${archive})
    NO_SLICES=$(find ${MOUNT_POINT} -name "${BASE}*.dar"|wc -l)
    SLICE_SIZE=$(ls -l --block-size=G "${MOUNT_POINT}/${BASE}.1.dar"|cut -d" " -f5)
    dar -l  "$MOUNT_POINT/${BASE}" > "$FILELIST" 
    RESULT=$?
    if [[ $RESULT -eq "0" ]]; then
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