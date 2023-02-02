#! /bin/bash


# mount a server dir using sshfs, as sshfs is a FUSE solution, root or
# programs running in the root context cannot access the server
#
# mount ${SERVER}:${SERVER_DIR} on ${MOUNT_POINT} at your machine to backup
# send Discord msg if not possible
mountDar () {
    mount |grep -E "${MOUNT_POINT} +type +fuse.sshfs" > /dev/null 2>&1
    RESULT=$?
    if [[ $RESULT == "0" ]]; then 
        return
    fi
    mkdir -p "${MOUNT_POINT}" 2>/dev/null
    sshfs "${SERVER}:${SERVER_DIR}" "${MOUNT_POINT}"
    mount |grep -E "${MOUNT_POINT} +type +fuse.sshfs" > /dev/null 2>&1
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        log "ERROR ${SERVER}:${SERVER_DIR} not mounted, exiting"
        exit 1
    fi
    if [[ $VERBOSE == "y" ]]; then 
        log "mount ${SERVER}:${SERVER_DIR} to ${MOUNT_POINT}, result: $RESULT"
    fi
}

function _date_time() {
    date +"%Y-%m-%d %H:%M:%S"
}


# write log message to log
# $1: the message
log () {
    echo "$(_date_time) $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

# check if an archive exists, before starting dar
# $1 argument: a variable, NOT is's value
# look here: https://stackoverflow.com/questions/540298/passing-arguments-by-reference
archiveExists () {
    local -n exists=$1
    DAR_ARCHIVE="${CURRENT_BACKUPDEF}_${MODE}_${DATE}"
    setArchivePath
    local COUNT=$(find "$MOUNT_POINT" -name "${DAR_ARCHIVE}*" -type f|wc -l)
    if [[ "$COUNT" != "0" ]]; then
        exists=1
    fi
}

# A little hack'ish, if LOCAL_BACKUP_DIR is set, use $MOUNT_POINT as the 
# local directory to store backups in. Useful for testing and if a server has 
# been mounted by other means
# 
mountPrereqs () {
    if [[ $LOCAL_BACKUP_DIR == "1" ]]; then
        if [[ $VERBOSE == "y" ]]; then 
            log "bypassing mounting a server dir..., \"LOCAL_BACKUP_DIR\" is set"
        fi
    else
        # mount the server somewhere
        mountDar
        if [[ $RESULT != "0" ]]; then
            sendDiscordMsg "ERROR ${SCRIPTNAME}: ${SERVER_DIR} not mounted on ${MOUNT_POINT}, exiting"
            exit 1
        fi
    fi
}


sendDiscordMsg () {
    log "$1"
    curl -i -H "Accept: application/json"  \
        -H "Content-Type:application/json"  \
        -X POST --data "{\"content\": \"$1\"}" \
        https://discord.com/api/webhooks/"${DISCORD_WEBHOOK}" \
        >/dev/null 2>&1
}


# copies dat_static (if found) to server as "dar_static_$VERSION"
# this way there is a better chance, you have the correct dar to restore
# some time in the future.
copyDarStatic () {
    # copy dar_static to server
    DAR_VERSION=$(dar_static --version |grep -oP "dar.*? version [\d.]+"|grep -oP "[\d.]+$")
    if [[ -n $DAR_VERSION ]]; then
        cp "$(which dar_static)"  "${MOUNT_POINT}/dar_static_$DAR_VERSION"
        if [[ $? == "0" ]]; then
            if [[ $VERBOSE == "y" ]]; then 
                log "dar_static version: $DAR_VERSION copied to: $MOUNT_POINT"
            fi
        else
            log "ERROR something went wrong, copying dar_static"
        fi
    else
        if [[ $VERBOSE == "y" ]]; then 
            log "dar_static not found"
        fi
    fi
}


setArchivePath () {
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"
}


# find newest archive for type
# $1: type is FULL|DIFF|INC
# NEWEST_ARCHIVE is set to the archive name only, not including path
findNewestForType () {
    NEWEST_ARCHIVE=""
    local PREV=""
    PREV=$(ls "${MOUNT_POINT}"/"${CURRENT_BACKUPDEF}"_"${1}"*.dar|tail -n 1)
    # {#} is the length of an env var
    if [[ ${#PREV} -lt 4 ]]; then
        log  "\"$1\" backup not found for definition \"${CURRENT_BACKUPDEF}\""
        return
    fi
    NEWEST_ARCHIVE=$(grep -E  "${CURRENT_BACKUPDEF}_${1}_[0-9]{4}-[0-9]{2}-[0-9]{2}" -o  <<< "$PREV" )
}


# function called to start processing a backup definition(a file in backups.d)
# MODE and DATE are defined in dar-backup.sh
# MOUNT_POINT is from the .conf file
#
runBackupDef () {
    DAR_ARCHIVE="${CURRENT_BACKUPDEF}_${MODE}_${DATE}"
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"
 
    local isExists=0
    archiveExists isExists
    if [[ "$isExists" != "0" ]]; then
        log "WARN archive: \"$DAR_ARCHIVE\" already exists, skipping"
        return
    fi
    if [[ $MODE == "FULL"  ]]; then 
      # backup
      backupTestRestore 
    else
        if [[ $MODE == "DIFF" ]]; then
            findNewestForType FULL
            if [[ ${#NEWEST_ARCHIVE} -lt 4 ]]; then
                log  "ERROR FULL backup not found for definition \"${CURRENT_BACKUPDEF}\""
            else
                log "Create DIFF compared to: $NEWEST_ARCHIVE"
                # backup
                diffBackupTestRestore  "${MOUNT_POINT}/$NEWEST_ARCHIVE" 
            fi
        else 
            if [[ $MODE == "INC" ]]; then
                findNewestForType DIFF
                if [[ ${#NEWEST_ARCHIVE} -lt 4 ]]; then
                    log  "ERROR DIFF backup not found for definition \"${CURRENT_BACKUPDEF}\""
                else
                    log "Create INC compared to: $NEWEST_ARCHIVE"
                    # backup
                    diffBackupTestRestore  "${MOUNT_POINT}/$NEWEST_ARCHIVE" 
                fi
            else
                log "ERROR neither FULL, DIFF nor INC specified for definition \"${CURRENT_BACKUPDEF}\""
            fi
        fi
    fi
}


# Shared test and restore functionality used by FULL and DIFF backup functions
#
# $1: the exit code from the backup operation
_TestRestore () {
    if [[ $1 == "0" ]]; then
        getNoFiles 
        if [[ "$VERBOSE" == "y" ]]; then 
            sendDiscordMsg  "dar backup of archive: ${DAR_ARCHIVE}, result: $RESULT, Saved: $NO_SAVED_FILES, Removed: $NO_REMOVED_FILES"
        fi
    # dar exit code 5 means some files were not backed up, report how many (if possible) and continue
    else 
        if [[ $1 == "5" ]]; then
            if [[ $DEBUG == "y" && $VERBOSE == "y" ]]; then
                local NO_ERRORS=""
                NO_ERRORS=$(grep -i "filesystem error" "${DEBUG_LOCATION}"|tail -n1|cut -f 2 -d " ")
                sendDiscordMsg "exit code = 5: $NO_ERRORS files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            else
                sendDiscordMsg "exit code = 5: unknown number of files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            fi
        else
            if [[ $VERBOSE == "y" ]]; then
                sendDiscordMsg  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
            else
                log  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
            fi
            return
        fi
    fi
    darTestBackup 
    darRestoreTest
}


# The standard recipe for backing up differentially a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
# $1 "${MOUNT_POINT}/$NEWEST_ARCHIVE" - the newest backup 
diffBackupTestRestore () {
    darDiffBackup "$1"
    _TestRestore $RESULT

    echo "SCRIPTDIRPATH: ${SCRIPTDIRPATH}"

    "${SCRIPTDIRPATH}/par2.sh" --archive-dir "${MOUNT_POINT}"  --archive "${DAR_ARCHIVE}"
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        log "par2 repair data generated for \"${DAR_ARCHIVE}\", result: $RESULT"
    else
        log "ERROR par repair data not created for \"${DAR_ARCHIVE}\""
        EVERYTHING_OK=1
    fi
}


# The standard recipe for backing up a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
backupTestRestore () {
    darBackup
    _TestRestore $RESULT
    "${SCRIPTDIRPATH}/par2.sh"  --archive-dir "${MOUNT_POINT}"  --archive "${DAR_ARCHIVE}"
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        log "par2 repair data generated for \"${DAR_ARCHIVE}\", result: $RESULT"
    else
        log "ERROR par repair data not created for \"${DAR_ARCHIVE}\""
        EVERYTHING_OK=1
    fi
}

# find number of files Saved and Removed in a backup
# store data in NO_SAVED_FILES and NO_REMOVED_FILES
getNoFiles () {
    sleep 1
    local TEMPFILE=/tmp/filelist_$(date +%s)
    NO_SAVED_FILES="unknown"
    NO_REMOVED_FILES="unknown"
    if [[ -f "$TEMPFILE"  ]]; then
        rm "$TEMPFILE"
        if [[ $? != "0" ]]; then
            return
        fi
    fi
    dar -Q -l "${ARCHIVEPATH}" > "$TEMPFILE"
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        return
    fi
    NO_SAVED_FILES=$(grep -E -c "\[Saved.*?\] +-" "$TEMPFILE")
    if [[ "$NO_SAVED_FILES" == "" ]]; then
        NO_SAVED_FILES="0"
    fi

    NO_REMOVED_FILES=$(grep -c " REMOVED ENTRY " "$TEMPFILE")
    if [[ "$NO_REMOVED_FILES" == "" ]]; then
        NO_REMOVED_FILES="0"
    fi

    rm "$TEMPFILE"
}


# explain exit code
# if $RESULT is a known value in this function, print a single line explanation
exitCodeExpl () {
    if [[ "$RESULT" == "11" ]]; then
        log "Exit code \"11\" means archive contains dirty files"
    fi
}


# do a dar backup
darBackup () {
    log "==========================================================="
    log "Start dar backup of: ${DAR_ARCHIVE}"
    log "==========================================================="

    dar -Q -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}"/../backups.d/"${CURRENT_BACKUPDEF}" \
        compress-exclusion verbose
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        "${SCRIPTDIRPATH}/manager.sh" --add-specific-archive "${DAR_ARCHIVE}" --local-backup-dir
        if [[ $? != "0" ]]; then
            log "ERROR archive \"${DAR_ARCHIVE}\" not added to it's catalog"
            EVERYTHING_OK=1
        fi
    else
        EVERYTHING_OK=1
    fi
    exitCodeExpl 
    log "Full backup result: $RESULT"
}

# do a dar differential backup
# $1: the archive to do the diff against (the -A option)
darDiffBackup () {
    grep _FULL_ "$1" > /dev/null 2>&1
    if [[ $? == "0" ]]; then
        log "==============================================================================="
        log "== Start dar DIFF backup of: ${DAR_ARCHIVE}, diff against: $1"
        log "==============================================================================="
    fi
    grep _DIFF_ "$1" > /dev/null 2>&1
    if [[ $? == "0" ]]; then
        log "==============================================================================="
        log "== Start dar INCREMENTAL backup of: ${DAR_ARCHIVE}, diff against: $1"
        log "==============================================================================="
    fi

    dar -Q -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}" \
        -A "$1" \
        compress-exclusion verbose 
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        "${SCRIPTDIRPATH}/manager.sh" --add-specific-archive "${DAR_ARCHIVE}"  --local-backup-dir
        if [[ $? != "0" ]]; then
            log "ERROR archive \"${DAR_ARCHIVE}\" not added to it's catalog"
            EVERYTHING_OK=1
        fi
    else
        EVERYTHING_OK=1
    fi
    exitCodeExpl

    log "Backup result: $RESULT"
}


# test a dar backup
darTestBackup () {
    # test the backup
    if [[ $VERBOSE == "y" ]]; then 
      log  "Test dar archive: ${ARCHIVEPATH}"
    fi
    dar -Q -t "${ARCHIVEPATH}" 
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        EVERYTHING_OK=1
        log "ERROR test of archive: ${DAR_ARCHIVE}, result: $RESULT"
    fi
    if [[ "$VERBOSE" == "y" ]]; then 
      sendDiscordMsg "dar test af archive: ${DAR_ARCHIVE}, result: $RESULT"
    fi
}


#  Try to find a file < 10MB for a restore test
#
#
darRestoreTest () {
    if [[ $VERBOSE == "y" ]]; then 
      log  "Test restore 1 file from archive: ${ARCHIVEPATH}"
    fi
    local RESTORE_DIR="/tmp/dar-restore"
    local FILELIST=/tmp/dar_list_49352
    local RESTORE_FILE=/tmp/dar_file_restore_53489
    
    dar -Q -l "${ARCHIVEPATH}" -ay |grep -E -v "\] +d[-rwx][-rwx][-rwx]"|grep -E "\[Saved\]"|cut -c45- |cut -f 3,5- |tail -n 100 > $FILELIST
    rm -f $RESTORE_FILE > /dev/null 2>&1

    LIST_SIZE=$(wc -c "$FILELIST"|cut -d" " -f1)
    if [[ $LIST_SIZE == "0" ]]; then
        if [[ $VERBOSE == "y" ]]; then 
          log "No files found for restore test in: ${ARCHIVEPATH}"
        fi
        return
    fi

    awk '{  if ($1 < 10000000) {
            print $0 
            exit
           }
    }' $FILELIST > "$RESTORE_FILE"

    RESTORE_FILE_SIZE=$(wc -c "$RESTORE_FILE"|cut -d" " -f1)
    if [[ $RESTORE_FILE_SIZE == "0" ]]; then
        sendDiscordMsg "== test restore discarded due to no file found under for 10000000 bytes in: ${ARCHIVEPATH}"
        return
    fi

    #file to restore inclusive path
    local TEST_RESTOREFILE=""
    TEST_RESTOREFILE=$(cut -f2 < "$RESTORE_FILE")
    if [[ $TEST_RESTOREFILE == "" ]]; then
        if [[ $VERBOSE == "y" ]]; then 
            log "No file found to perform restore test on, this might be an error"
        fi
        return
    fi
    
    # remove the test restore top dir, before restoring
    rm -fr "$RESTORE_DIR" > /dev/null  2>&1
    mkdir -p "$RESTORE_DIR"

    if [[ $VERBOSE == "y" ]]; then 
      log "Restore test of file: \"${TEST_RESTOREFILE}\"" 
    fi
    dar -Q -x "${ARCHIVEPATH}" -R "$RESTORE_DIR" -g "${TEST_RESTOREFILE}" ${FSA_SCOPE_NONE} -B "${SCRIPTDIRPATH}/../conf/defaults-rc"
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        EVERYTHING_OK=1
    fi
    if [[ $VERBOSE == "y" ]]; then 
      sendDiscordMsg "dar restore test of archive: \"$DAR_ARCHIVE\", restored file: \"${TEST_RESTOREFILE}\" result: $RESULT"
    fi
}
