#! /bin/bash
# Run script as a non-root user if sshfs mounts are used
# 
# Will do full backups if called as "dar-backup.sh"
# Will do differential backups if called as "dar-diff-backup.sh"
# create a link like this:  "ln -s dar-backup.sh  dar-diff-backup.sh"


# which mode: FULL, DIFF or INC
SCRIPTNAME=$(basename "$0")

VERSION=@@DEV-VERSION@@

MODE=""
BACKUPDEF=""
FSA_SCOPE_NONE="" 
CURRENT_BACKUPDEF=""
DAR_ARCHIVE=""
ARCHIVEPATH=""
LOCAL_BACKUP_DIR=""
export EVERYTHING_OK=0 # report this at the end, will be set to 1 if something goes wrong
export CMD_DEBUG="n"
export CMD_USE_CATALOGS="n"
export VERBOSE="n"
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
      --fsa-scope-none)
          FSA_SCOPE_NONE=" --fsa-scope none "
          ;;
      --debug)
          CMD_DEBUG=y
          ;;
      --verbose)
          VERBOSE="y"
          ;;
      --run-restore-test)
          RUN_RESTORE_TEST="y"
          shift
          DAR_ARCHIVE="$1"
          ;;
      --use-catalogs)
          CMD_USE_CATALOGS="y"
          ;;
      --help|-h)
          echo "$SCRIPTNAME [--backupdef|-d <backup definition>] [--local-backup-dir] [--fsa-scope-none] [--run-restore-test  <dar archive>] [--version|-v] [--verbose] [--debug] [--help|-h]"
          echo "   --backupdef <backup definition>, run a single definition (a filename in backups.d/)"
          echo "   --local-backup-dir, don't sshfs-mount a remote directory on MOUNT_POINT"
          echo "   --fsa-scope-none, useful when restoring to different file system type"
          echo "   --verbose, more log messages included being sent to Discord"
          echo "   --run-restore-test <dar archive> (archive name without <slice#>.dar)"
          echo "   --debug, give bash the '-x' option to log all activity to configured file"
          echo "   --use-catalogs, override default config file setting to use dar catalogs"
          echo "   --help, this terse usage info"
          exit
          ;;
      --verbose)
          VERBOSE="y"
          ;;
      --version|-v)
          echo "$SCRIPTNAME $VERSION"
          echo "Licensed under GNU GENERAL PUBLIC LICENSE v3, see \"LICENSE\" file for details"
          exit
          ;;
      *)
          echo option \"$1\" not recognized, exiting
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
log "FSA_SCOPE_NONE=${FSA_SCOPE_NONE}"
log "RUN_RESTORE_TEST=${RUN_RESTORE_TEST}"
log "CMD_DEBUG=${CMD_DEBUG}"
log "CMD_USE_CATALOGS=${CMD_USE_CATALOGS}"
log "VERBOSE=${VERBOSE}"

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
        log "start processing backup definition: ${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}"
        runBackupDef
    done
  else
    if [[ -f "${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"  ]]; then
        CURRENT_BACKUPDEF="$BACKUPDEF"
        log "start processing a single backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF}"
        runBackupDef
    else 
      log "ERROR backup definition: ${SCRIPTDIRPATH}/../backups.d/${BACKUPDEF} does not exist"
    fi
  fi
fi
if [[ "$EVERYTHING_OK" == "0" ]]; then
  sendDiscordMsg "$SCRIPTNAME ended without errors"
else
  sendDiscordMsg "ERROR: $SCRIPTNAME ended with errors"
fi 
exit "$EVERYTHING_OK"
