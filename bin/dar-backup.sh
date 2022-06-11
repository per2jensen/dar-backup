#! /bin/bash
# Run script as a non-root user if sshfs mounts are used
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"


# which mode: FULL, DIFF or INC
SCRIPTNAME=$(basename "$0")



MODE=""
BACKUPDEF=""
FSA_SCOPE_NONE="" 
CURRENT_BACKUPDEF=""
DAR_ARCHIVE=""
ARCHIVEPATH=""
LOCAL_BACKUP_DIR=""
LIST_FILES=""  # boolean: list files to back up
export EVERYTHING_OK=0 # report this at the end, will be set to 1 if something goes wrong
CMD_DEBUG="n"
RUN_RESTORE_TEST="n"

export NO_SAVED_FILES="unknown"
export NO_REMOVED_FILES="unknown"


# Get the options
while [ -n "$1" ]; do
  case "$1" in
      --backupdef|-d)
          shift
          BACKUPDEF="$1"
          ;;
      --local-backup-dir)
          echo "$MOUNT_POINT" used as local backup directory....
          LOCAL_BACKUP_DIR=1
          ;;
      --list-files|-l)
          LIST_FILES=1
          ;;
      --fsa-scope-none)
          FSA_SCOPE_NONE=" --fsa-scope none "
          ;;
      --debug)
          CMD_DEBUG=y
          ;;
      --run-restore-test)
          RUN_RESTORE_TEST="y"
          shift
          DAR_ARCHIVE="$1"
          ;;
      --help|-h)
          echo "$SCRIPTNAME --help|-h  [--backupdef|-d <backup definition>]  [--list-files|-l] [--local-backup-dir] [--fsa-scope-none] [--run-restore-test  <dar archive>]  [--debug]"
          echo "   --backupdef, where <backup definition> is a filename in backups.d/"
          echo "   --list-files, list files that will be backed up (slow, be patient)"
          echo "   --local-backup-dir, don't mount a remote directory for backup, test, restore operations"
          echo "   --fsa-scope-none, useful when restoring to another type of file system, than when backup was done (for example the restore test)"
          echo "   --debug, give bash the '-x' option to log all activity"
          echo "   --run-restore-test, where <dar archive> is an existing archive"
          exit
          ;;
  esac
  shift
done


export DATE=""
DATE=$(date -I)

export SCRIPTPATH=""
SCRIPTPATH=$(realpath "$0")

export SCRIPTDIRPATH=""
SCRIPTDIRPATH=$(dirname "$SCRIPTPATH")

source "${SCRIPTDIRPATH}/../conf/dar-backup.conf"

if [[ $DEBUG == "y" || $CMD_DEBUG == "y" ]]; then
  set -x
  exec > >(tee -a "${DEBUG_LOCATION}")  2>&1
fi

source "${SCRIPTDIRPATH}/dar-util.sh"

STARTTIME="$(date -Iseconds)"
log =======================================================
log "  $SCRIPTNAME started: $STARTTIME"
log =======================================================
log "BACKUPDEF=${BACKUPDEF}"
log "LOCAL_BACKUP_DIR=${LOCAL_BACKUP_DIR}"
log "LIST_FILES=${LIST_FILES}"
log "FSA_SCOPE_NONE=${FSA_SCOPE_NONE}"
log "RUN_RESTORE_TEST=${RUN_RESTORE_TEST}"
log "CMD_DEBUG=${CMD_DEBUG}"

if [[ $SCRIPTNAME == "dar-backup.sh"  ]]; then
  MODE=FULL
fi
if [[ $SCRIPTNAME == "dar-diff-backup.sh"  ]]; then
  MODE=DIFF
fi
if [[ $SCRIPTNAME == "dar-inc-backup.sh"  ]]; then
  MODE=INC
fi

if [[ $MODE == "" ]]; then
    log "ERROR script called with wrong name: $0, exiting"
    exit 1
fi


# make sure mounts are in order
mountPrereqs

# copy dar_static to server
copyDarStatic

# check if a restore test is chosen
if [[ "$RUN_RESTORE_TEST" == "y"  ]]; then
  # set up variables the restore function expects
  setArchivePath
  darRestoreTest
else
  # check if a single backup definition is to be run
  if [[ "$BACKUPDEF" == "" ]]; then
    # loop over backup definition in backups.d/
    for CURRENT_BACKUPDEF in "${SCRIPTDIRPATH}"/../backups.d/*; do
        CURRENT_BACKUPDEF=$(basename "$CURRENT_BACKUPDEF")
        if [[ $LIST_FILES  ==  "1" ]]; then
          log "== list files to backup, mode: ${MODE}, definition: ${BACKUPDEF}"
          listFilesToBackup
        else
          log "== start processing backup definition: ${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}"
          runBackupDef
        fi
    done
  else
    if [[ -f "${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"  ]]; then
        CURRENT_BACKUPDEF="$BACKUPDEF"
        if [[ $LIST_FILES  ==  "1" ]]; then
          log "== list files to backup, mode: ${MODE}, definition: ${BACKUPDEF}"
          listFilesToBackup
        else
          log "== start processing a single backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"
          runBackupDef
        fi
    else 
      log "ERROR backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF} does not exist"
    fi
  fi
fi
exit "$EVERYTHING_OK"
