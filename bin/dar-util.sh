

# mount a server dir using sshfs, as sshfs is a FUSE solution, root or
# programs running in the root context cannot access the server
#
# mount ${SERVER}:${SERVER_DIR} on ${MOUNT_POINT} at your machine to backup
# send Discord msg if not possible
mountDar () {
    mount |egrep "${MOUNT_POINT} +type +fuse.sshfs" > /dev/null 2>&1
    RESULT=$?
    if [[ $RESULT == "0" ]]; then 
        return
    fi
    mkdir -p ${MOUNT_POINT} 2>/dev/null
    sshfs ${SERVER}:${SERVER_DIR} ${MOUNT_POINT}
    mount |egrep "${MOUNT_POINT} +type +fuse.sshfs" > /dev/null 2>&1
    RESULT=$?
    log "mount ${SERVER}:${SERVER_DIR} to ${MOUNT_POINT}, result: $RESULT"
}

function _date_time() {
    date +"%Y-%m-%d %H:%M:%S"
}


# write log message to log
# $1: the message
log () {
    echo "$(_date_time) $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}


# A little hack'ish, if LOCAL_BACKUP_DIR is set, use $MOUNT_POINT as the 
# local directory to store backups in. Useful for testing and if a server has 
# been mounted by other means
# 
mountPrereqs () {
    if [[ $LOCAL_BACKUP_DIR == "1" ]]; then
        log "bypassing mounting a server dir..., \"LOCAL_BACKUP_DIR\" is set"
    else
        # mount the server somewhere
        mountDar
        if [[ $RESULT != "0" ]]; then
            sendDiscordMsg "${SCRIPTNAME}: ${SERVER_DIR} not mounted on ${MOUNT_POINT}, exiting"
            exit 1
        fi
    fi
}


sendDiscordMsg () {
    log "== send Discord message: $1"
    curl -i -H "Accept: application/json"  \
        -H "Content-Type:application/json"  \
        -X POST --data "{\"content\": \"$1\"}" \
        https://discord.com/api/webhooks/${DISCORD_WEBHOOK} \
        >/dev/null 2>&1
}


# copies dat_static (if found) to server as "dar_static_$VERSION"
# this way there is a better chance, you have the correct dar to restore
# some time in the future.
copyDarStatic () {
    # copy dar_static to server
    DAR_VERSION=$(dar_static --version |grep -oP "dar.*? version [\d.]+"|grep -oP "[\d.]+$")
    if [[ ! -z $DAR_VERSION ]]; then
        cp "$(which dar_static)"  "${MOUNT_POINT}/dar_static_$DAR_VERSION"
        if [[ $? == "0" ]]; then
            log "== dar_static version: $DAR_VERSION copied to: $MOUNT_POINT"
        else
            log "== something went wrong, copying dar_static"
        fi
    else
        log "== dar_static not found"
    fi
}


# function called to start processing a backup definition(a file in backups.d)
# MODE and DATE are defined in dar-backup.sh
# MOUNT_POINT is from the .conf file
#
runBackupDef () {

    DAR_ARCHIVE="${CURRENT_BACKUPDEF}_${MODE}_${DATE}"
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"

 
    if [[ $MODE == "FULL"  ]]; then 
      # backup
      backupTestRestore 
    else
      PREV=`ls "${MOUNT_POINT}"|grep -P "${CURRENT_BACKUPDEF}_FULL"|grep dar$|tail -n 1`
      if [[ ${#PREV} -lt 4 ]]; then
        log  "ERROR FULL backup not found for definition \"${CURRENT_BACKUPDEF}\", exiting"
        exit 100 
      fi
      NEWEST_ARCHIVE=${PREV%%.*}
      log "NEWEST archive: $NEWEST_ARCHIVE"
      # backup
      diffBackupTestRestore  "${MOUNT_POINT}/$NEWEST_ARCHIVE" 
    fi
}


# Shared test and restore functionality used by FULL and DIFF backup functions
#
# $1: the exit code from the backup operation
_TestRestore () {
    if [[ $1 == "0" ]]; then
        sendDiscordMsg  "dar backup of archive: ${DAR_ARCHIVE}, result: $RESULT"
    # dar exit code 5 means some files were not backed up, report how many (if possible) and continue
    else if [[ $1 == "5" ]]; then
            if [[ $DEBUG == "y" ]]; then
                local NO_ERRORS=$(grep -i "filesystem error" "${DEBUG_LOCATION}"|tail -n1|cut -f 2 -d " ")
                sendDiscordMsg "exit code = 5: $NO_ERRORS files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            else
                sendDiscordMsg "exit code = 5: unknown number of files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            fi
        else
            sendDiscordMsg  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
            return
        fi
    fi
    darTestBackup 
    RESULT=$?
    sendDiscordMsg  "dar test of archive: ${DAR_ARCHIVE}, result: $RESULT"
    darRestoreTest
    RESULT=$?
    sendDiscordMsg  "dar restore test of archive: ${DAR_ARCHIVE}, result: $RESULT"
}


# The standard recipe for backing up differentially a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
# $1 "${MOUNT_POINT}/$NEWEST_ARCHIVE" - the newest backup 
diffBackupTestRestore () {
    darDiffBackup "$1"
    RESULT=$?
    _TestRestore $RESULT
}



# The standard recipe for backing up a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
backupTestRestore () {
    darBackup
    _TestRestore $RESULT
}


# do a dar backup
darBackup () {
    log "==========================================================="
    log "Start dar backup of: ${DAR_ARCHIVE}"
    log "==========================================================="

    dar -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}" \
        par2 \
        compress-exclusion verbose $DRY_RUN
    RESULT=$?
    log "Full backup result: $RESULT"
}


# do a dar differential backup
# $1: the archive to do the diff against (the -A option)
darDiffBackup () {
    log "==============================================================================="
    log "== Start dar diff backup of: ${DAR_ARCHIVE}, diff against: $1"
    log "==============================================================================="
    dar -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}" \
        -A "$1" \
        par2 \
        compress-exclusion verbose $DRY_RUN
    RESULT=$?
    log "Diff backup result: $RESULT"
}


# test a dar backup
darTestBackup () {
  # test the backup
  log  "== Test dar archive: ${ARCHIVEPATH}"
  dar -t "${ARCHIVEPATH}" $DRY_RUN
  RESULT=$?
  sendDiscordMsg "dar test af archive: ${DAR_ARCHIVE}, result: $RESULT"
}


#  Try to find a file < 10MB for a restore test
#
#
darRestoreTest () {
    log  "== Test restore 1 file from archive: ${ARCHIVEPATH}"
    local FILELIST=/tmp/dar_list_49352
    local RESTORE_FILE=/tmp/dar_file_restore_53489
    
    dar -l "${ARCHIVEPATH}" -ay $DRY_RUN|egrep -v "d[-rw][-rw]"|egrep "\[Saved\]"|cut -c45- |cut -f 3,5- |tail -n 100 > $FILELIST
    rm -f $RESTORE_FILE > /dev/null 2>&1
    awk '{  if ($1 < 10000000) {
            print $0 
            exit
           }
    }' $FILELIST > "$RESTORE_FILE"

    local TEST_RESTOREFILE=$(cat "$RESTORE_FILE"|cut -f2)
    
    local DAR_RESTORE_DIR=`dirname "$TEST_RESTOREFILE"|sed 's/^\t+//'`
    local DAR_RESTORE_FILE=`basename  "$TEST_RESTOREFILE"`
    local TOPDIR=`echo ${DAR_RESTORE_DIR} |sed -E -n 's|(^.*?/).*|\1|p'`
    if [[ $TOPDIR != "" ]]; then
        rm -fr /tmp/${TOPDIR}
    fi
    log "== Restore test of file: \"/tmp/${DAR_RESTORE_DIR}/${DAR_RESTORE_FILE}\""
    dar -x "${ARCHIVEPATH}" -R /tmp -g "$DAR_RESTORE_DIR" -I "$DAR_RESTORE_FILE" $DRY_RUN
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        if [[ -f /tmp/${DAR_RESTORE_DIR}/${DAR_RESTORE_FILE} ]]; then
            sendDiscordMsg "dar restore test of archive: \"$DAR_ARCHIVE\" is OK, restored file: \"${DAR_RESTORE_FILE}\" result: $RESULT"
        else
            log "== File: \"${DAR_RESTORE_FILE}\" not restored to: ${DAR_RESTORE_DIR}"
        fi
    else
        log "== dar restore failed, exit code: $RESULT"
    fi
}
