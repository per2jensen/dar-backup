#!/bin/bash
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
# mount a server dir using sshfs, as sshfs is a FUSE solution, root or
# programs running in the root context cannot access the server
#
# mount ${SERVER}:${SERVER_DIR} on ${MOUNT_POINT} at your machine to backup
# send Discord msg if not possible
mountDar () {
    local result
    mount |grep -E "${MOUNT_POINT} +type +fuse.sshfs" > /dev/null 2>&1
    result=$?
    if [[ "$result" -eq "0" ]]; then 
        return
    fi
    mkdir -p "${MOUNT_POINT}" 2>/dev/null || { log_error "MOUNT_POINT could not be created"; exit 1; }
    sshfs -F  "${SSH_CONFIG}" "${SERVER}:${SERVER_DIR}" "${MOUNT_POINT}"
    mount |grep -E -q "${MOUNT_POINT} +type +fuse.sshfs" 
    result=$?
    if [[ "$VERBOSE" == "y" ]]; then 
        log "mount ${SERVER}:${SERVER_DIR} to ${MOUNT_POINT}, result: $result"
    fi
    if [[ $result -ne "0" ]]; then
        log_error "${SERVER}:${SERVER_DIR} not mounted, exiting"
        exit 1
    fi
}

_date_time() {
    local _date=$(date +"%Y-%m-%d %H:%M:%S,%N")
    echo "${_date:0:23}"
}


# return 1 if a backup definition contains underscores
# $1: the definition name to check
is_definition_name_ok() {
    [[ $1 == *_* ]] &&  return 1 || return 0
}

# write log message to log
# $1: the message 
log () {
    echo "$(_date_time) $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

# only print this if --verbose option has been set or config file VERBOSE="y"
log_verbose () {
    if [[ "$VERBOSE" == "y" ]]; then
        echo "$(_date_time) $1" | tee -a "$LOG_LOCATION/dar-backup.log"
    fi
}


log_error () {
    echo -e "$(_date_time) \e[1m\e[31mERROR\e[0m $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

log_warn () {
    echo -e "$(_date_time) \e[35mWARN\e[0m $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

log_success () {
    echo -e "$(_date_time) \e[1m\e[32mSUCCESS\e[0m $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

log_fail () {
    echo -e "$(_date_time) \e[1m\e[31mFAIL\e[0m $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}



# check if an archive exists, before starting dar
# $1 argument: a variable, NOT is's value
# look here: https://stackoverflow.com/questions/540298/passing-arguments-by-reference
archiveExists () {
    local -n exists=$1 # reference to supplied argument
    DAR_ARCHIVE="${CURRENT_BACKUPDEF}_${MODE}_${DATE}"
    setArchivePath
    local COUNT=$(find "$MOUNT_POINT" -name "${DAR_ARCHIVE}*" -type f|wc -l)
    if [[ "$COUNT" -ne "0" ]]; then
        exists=1
    fi
}

# A little hack'ish, if LOCAL_BACKUP_DIR is set, use $MOUNT_POINT as the 
# local directory to store backups in. Useful for testing and if a server has 
# been mounted by other means
# 
mountPrereqs () {
    if [[ $LOCAL_BACKUP_DIR -eq 1 ]]; then
        if [[ "$VERBOSE" == "y" ]]; then 
            log "bypassing mounting a server dir..., \"LOCAL_BACKUP_DIR\" is set"
        fi
    else
        # mount the server somewhere
        mountDar
    fi
}


sendDiscordMsg () {
    log "$1"
    curl -H "Accept: application/json"  \
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
        if [[ $? -eq 0 ]]; then
            log_verbose "dar_static version: $DAR_VERSION copied to: $MOUNT_POINT"
        else
            log_error "something went wrong, copying dar_static"
        fi
    else
        if [[ "$VERBOSE" == "y" ]]; then 
            log "dar_static not found"
        fi
    fi
}


setArchivePath () {
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"
}


# find newest archive for type
# $1: type is FULL|DIFF|INC
# $2: named variable to deliver result to
# "archive" is set to the archive name only, not including path
findNewestForType () {
    local -n archive=$2
    local PREV=""
    PREV=$(ls "${MOUNT_POINT}"/"${CURRENT_BACKUPDEF}"_"${1}"*.dar|tail -n 1)
    archive=$(grep -E  "${CURRENT_BACKUPDEF}_${1}_[0-9]{4}-[0-9]{2}-[0-9]{2}" -o  <<< "$PREV" )
}


# function called to start processing a backup definition(a file in backups.d)
# MODE and DATE are defined in dar-backup.sh
# MOUNT_POINT is from the .conf file
#
runBackupDef () {
    DAR_ARCHIVE="${CURRENT_BACKUPDEF}_${MODE}_${DATE}"
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"
 
    local isExists=0
    local newest_archive=""
    archiveExists isExists
    if [[ "$isExists" -ne "0" ]]; then
        log_warn "archive: \"$DAR_ARCHIVE\" already exists, skipping"
        return
    fi
    if [[ "$MODE" == "FULL"  ]]; then 
      # backup
      backupTestRestore 
    else
        if [[ "$MODE" == "DIFF" ]]; then
            findNewestForType FULL newest_archive 
            if [[ ${#newest_archive} -lt 4 ]]; then
                log_error "FULL backup not found for definition \"${CURRENT_BACKUPDEF}\""
            else
                log "Create DIFF compared to: $newest_archive"
                # backup
                diffBackupTestRestore  "${MOUNT_POINT}/$newest_archive" 
            fi
        else 
            if [[ $MODE == "INC" ]]; then
                findNewestForType DIFF newest_archive
                if [[ ${#newest_archive} -lt 4 ]]; then
                    log_error "DIFF backup not found for definition \"${CURRENT_BACKUPDEF}\""
                else
                    log "Create INC compared to: $newest_archive"
                    # backup
                    diffBackupTestRestore  "${MOUNT_POINT}/$newest_archive" 
                fi
            else
                log_error "neither FULL, DIFF nor INC specified for definition \"${CURRENT_BACKUPDEF}\""
            fi
        fi
    fi
}


# Shared test and restore functionality used by FULL and DIFF backup functions
#
# $1: the exit code from the backup operation
process_backup_result () {
    local result="$1"
    if [[ $1 -eq "0" ]]; then
        local no_saved_files="unknown"
        local no_removed_files="unknown"
        if [[ "$VERBOSE" == "y" ]]; then 
            getNoFiles no_saved_files  no_removed_files
            sendDiscordMsg  "dar backup of archive: ${DAR_ARCHIVE}, result: $result, Saved: $no_saved_files, Removed: $no_removed_files"
        fi
    # dar exit code 5 means some files were not backed up, report how many (if possible) and continue
    else 
        if [[ "$1" -eq "5" ]]; then
            if [[ "$DEBUG" == "y" ]]; then
                local no_errors=""
                no_errors=$(grep -i "filesystem error" "${DEBUG_LOCATION}"|tail -n1|cut -f 2 -d " ")
                log_warn "exit code = 5: $no_errors files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            else
                log_warn "exit code = 5: unknown number of files were not backed up in archive: ${DAR_ARCHIVE}, continuing testing the archive"
            fi
        else
            log_error  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
            return
        fi
    fi
}

# Complete various tasks after a backup
# test the archive, do a test restore, produce .par2 files
#
# $1: the exit code from the backup operation as a named referenced var
tasksAfterBackup () {
    local -n result2=$1
    process_backup_result "$result2"

    if [[ $result2 -eq 0 || $result2 -eq 5 ]]; then
        darTestBackup 

        darRestoreTest

        "${SCRIPTDIRPATH}/par2.sh" --archive-dir "${MOUNT_POINT}"  --archive "${DAR_ARCHIVE}"
        if [[ $? -eq "0" ]]; then
            log "par2 repair data generated for \"${DAR_ARCHIVE}\", result: 0"
        else
            log_error "par repair data not created for \"${DAR_ARCHIVE}\""
            BACKUP_OK=1
        fi
    fi
}

# The standard recipe for backing up differentially a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
# $1 "${MOUNT_POINT}/$NEWEST_ARCHIVE" - the newest backup 
diffBackupTestRestore () {
    local backup_result
    darDiffBackup "$1" backup_result
    tasksAfterBackup backup_result
}


# The standard recipe for backing up a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
backupTestRestore () {
    local backup_result
    darBackup backup_result
    tasksAfterBackup backup_result
}

# find number of files Saved and Removed in a backup
# $1: referenced var no_saved_files
# $2: referenced var no_removed_files
getNoFiles () {
    local -n saved_files=$1
    local -n removed_files=$2
    sleep 1
    local TEMPFILE=/tmp/filelist_$(date +%s)
    saved_files="unknown"
    removed_files="unknown"
    if [[ -f "$TEMPFILE"  ]]; then
        rm "$TEMPFILE"
        if [[ $? -ne "0" ]]; then
            return
        fi
    fi
    dar -Q -l "${ARCHIVEPATH}" > "$TEMPFILE"
    if [[ $? -ne 0 ]]; then
        return
    fi
    saved_files=$(grep -E -c "\[Saved.*?\] +-" "$TEMPFILE")
    if [[ "$saved_files" == "" ]]; then
        saved_files="0"
    fi

    removed_files=$(grep -c " REMOVED ENTRY " "$TEMPFILE")
    if [[ "$removed_files" == "" ]]; then
        removed_files="0"
    fi

    rm "$TEMPFILE"  || log_error "\"$TEMPFILE\" could not be deleted"
}


# explain exit code
# if $1 is a known value in this function, print a single line explanation
exitCodeExpl () {
    if [[ "$1" == "11" ]]; then
        log_warn "Exit code \"11\" means archive contains dirty files"
    fi
}

# print a log line with the result of a catalog operation
# set the CATALOG_OK env var if an error happened
# $1: the exit code from manager.sh script
catalogOpsResult () {
    local catalogresult="$1"
    case $catalogresult in
    0)
        log "${DAR_ARCHIVE} added to it's catalog" 
        ;;
    5) 
        log_warn "Something did not go completely right adding \"${DAR_ARCHIVE}\" to it's catalog"
        ;;
    *)
        log_error "Some error was found while adding \"${DAR_ARCHIVE}\" to it's catalog"
        CATALOG_OK=1
        ;;
    esac                
}


# do a dar backup
# $1: a variable to pass back the result
darBackup () {
    local -n result=$1 # write result to to $1 variable
    local _result
    log "Start FULL backup of: ${DAR_ARCHIVE}"

    dar -Q -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}"/../backups.d/"${CURRENT_BACKUPDEF}" \
        compress-exclusion verbose
    _result=$?
    if [[ $_result -eq "0" ]]; then
        if [[ "$CMD_USE_CATALOGS" == "y" || "$USE_CATALOGS" == "y" ]]; then
            "${SCRIPTDIRPATH}/manager.sh" --add-specific-archive "${DAR_ARCHIVE}" --local-backup-dir
            catalogOpsResult "$?"
        fi
    else
        BACKUP_OK=1
    fi
    exitCodeExpl "$_result" 
    result=$_result
    log "Backup result: $result"
}

# do a dar differential backup
# $1: the archive to do the diff against (the -A option)
# $2: the variable to store the result in (via a name reference, to avoid a global var)
darDiffBackup () {
    local -n result=$2 # reference to supplied argument
    local _result
    echo "$1" | grep -q _FULL_ 
    if [[ $? -eq "0" ]]; then
        log "Start DIFF backup of: ${DAR_ARCHIVE}, diff against: $1"
    fi
    echo "$1" | grep -q _DIFF_ 
    if [[ "$?" -eq "0" ]]; then
        log "Start INCREMENTAL backup of: ${DAR_ARCHIVE}, diff against: $1"
    fi
    dar -Q -c "${ARCHIVEPATH}" \
        -N \
        -B "${SCRIPTDIRPATH}/../backups.d/${CURRENT_BACKUPDEF}" \
        -A "$1" \
        compress-exclusion verbose 
    _result=$?
    if [[ "$_result" -eq "0" ]]; then
        if [[ "$CMD_USE_CATALOGS" == "y" || "$USE_CATALOGS" == "y" ]]; then
            "${SCRIPTDIRPATH}/manager.sh" --add-specific-archive "${DAR_ARCHIVE}" --local-backup-dir
            catalogOpsResult "$?"
        fi
    else
        BACKUP_OK=1
    fi
    exitCodeExpl "$_result"
    result=$_result
    log "Backup result: $result"
}


# test a dar backup
darTestBackup () {
    local result
    # test the backup
    log  "Test dar archive: ${ARCHIVEPATH}"
    dar -Q -t "${ARCHIVEPATH}" 
    result=$?
    if [[ $result -ne 0 ]]; then
        BACKUP_OK=1
        log_error "Test of archive: ${DAR_ARCHIVE}, result: $result"
    else
        log "Test of archive: ${DAR_ARCHIVE}, result: $result"
    fi
    if [[ "$VERBOSE" == "y" ]]; then 
      sendDiscordMsg "dar test af archive: ${DAR_ARCHIVE}, result: $result"
    fi
}


#  Try to find a file < 10MB for a restore test
#
#
darRestoreTest () {
    log  "Test restoring 1 file from archive: ${ARCHIVEPATH}"
    local filelist=""
    filelist=$(mktemp) || { BACKUP_OK=1; log_error "temporary filelist name not set."; return; }
    
    local restore_file=""
    restore_file=$(mktemp)  || { BACKUP_OK=1; log_error "temporary restore_file name not set."; return; }

    local result
    dar -Q -l "${ARCHIVEPATH}" -ay |grep -E -v "\] +d[-rwx][-rwx][-rwx]"|grep -E "\[Saved\]"|cut -c45- |cut -f 3,5- |tail -n 100 > $filelist

    rm -f $restore_file > /dev/null 2>&1

    local list_size=""
    list_size=$(wc -c < "$filelist")
    if [[ "$list_size" -eq "0" ]]; then
        log_verbose "No files found for restore test in: ${ARCHIVEPATH}"
        return
    fi
    awk '{  if ($1 < 10000000) {
            print $0 
            exit
           }
    }' $filelist > "$restore_file"
    log_verbose "restore_file: $restore_file"

    local restore_file_size=""
    restore_file_size=$(wc -c < "$restore_file")
    log_verbose "restore_filesize: $restore_file_size"
    if [[ "$restore_file_size" -eq "0" ]]; then
        sendDiscordMsg "== test restore discarded due to no file found under for 10000000 bytes in: ${ARCHIVEPATH}"
        return
    fi

    #file to restore inclusive path
    local test_restorefile=""
    test_restorefile=$(cut -f2 < "$restore_file")
    if [[ "$test_restorefile" == "" ]]; then
        log_verbose "No file found to perform restore test on, this might be an error"
        return
    fi
    
    # remove the test restore top dir, before restoring
    local restore_dir=""
    restore_dir=$(mktemp -d)  || { BACKUP_OK=1; log_error "temporary restore_dir directory not set."; return; }
    

    log_verbose "ARCHIVEPATH: \"$ARCHIVEPATH\""
    log_verbose "restore_dir: \"$restore_dir\""
    log_verbose "FSA_SCOPE_NONE: $FSA_SCOPE_NONE"
    log_verbose "SCRIPTDIRPATH: \"$SCRIPTDIRPATH\""
    log "Test restoring file: \"$test_restorefile\"" 

    if [[ $FSA_SCOPE_NONE != "" ]]; then
        dar -Q -x "$ARCHIVEPATH" -R "$restore_dir" -g "$test_restorefile" --fsa-scope none -B "$SCRIPTDIRPATH/../conf/defaults-rc"
        _result=$?
        if [[ "$_result" -ne "0" ]]; then
            BACKUP_OK=1
        fi
    else
        dar -Q -x "$ARCHIVEPATH" -R "$restore_dir" -g "$test_restorefile" -B "$SCRIPTDIRPATH/../conf/defaults-rc"
        _result=$?
        if [[ "$_result" -ne "0" ]]; then
            BACKUP_OK=1
        fi
    fi

    # check restored file exists
    local testpath="${restore_dir}/${test_restorefile}"
    log "Check if restored file \"$testpath \" exists"
    if [[ -f  "$testpath"  || -h "$testpath" ]]; then
        log "Restored file was found"
    else
        log_error "no, the file is not found"
        BACKUP_OK=1
    fi

    rm -fr "$restore_dir" || log_error "Could not delete restore_dir directory: $restore_dir"
    rm -f "$restore_file" || log_error "Could not delete restore_file file: $restore_file"
    rm -f "$filelist" || log_error "Could not delete filelist file: $filelist"

    if [[ "$VERBOSE" == "y" ]]; then 
      sendDiscordMsg "dar restore test of archive: \"$DAR_ARCHIVE\", restored file: \"${test_restorefile}\" result: $_result"
    fi
}
