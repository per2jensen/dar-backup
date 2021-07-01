

# mount a server dir using sshfs, as sshfs is a FUSE solution, root or
# programs running in the root context cannot access the server
#
# mount ${SERVER}:${SERVER_DIR} on ${MOUNT_POINT} at your machine to backup
# send Discord msg if not possible
mountDar () {
    mount |egrep "${MOUNT_POINT} +type +fuse.sshfs"
    RESULT=$?
    if [[ $RESULT == "0" ]]; then 
        return 0
    fi
    # mount ${SERVER_DIR} on ${MOUNT_POINT}
    mkdir -p ${MOUNT_POINT} 2>/dev/null
    sshfs ${SERVER}:${SERVER_DIR} ${MOUNT_POINT}
    mount |egrep "${MOUNT_POINT} +type +fuse.sshfs"
    if [[ $? == "0" ]]; then
        return 0
    fi

    # error, mount did not succeed
    return 1
}

function _date_time() {
    date +"%Y-%m-%d %H:%M:%S"
}


# write log message to log
# $1: the message
log () {
    echo "$(_date_time) $1" | tee -a "$LOG_LOCATION/dar-backup.log"
}

mountPrereqs () {
    # mount the server somewhere
    mountDar
    RESULT=$?
    if [[ $RESULT != "0" ]]; then
        sendDiscordMsg "${SCRIPTNAME}: ${SERVER_DIR} not mounted on ${MOUNT_POINT}, exiting"
        exit 1
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
# BACKUP_NAME comes from the backup definition
#
# $1: filename of the backup definition in backups.d
runBackupDef () {
    local backupdef="$1"
    source "${SCRIPTDIRPATH}/../backups.d/${backupdef}"

    DAR_ARCHIVE="${BACKUP_NAME}_${MODE}_${DATE}"
    ARCHIVEPATH="${MOUNT_POINT}/${DAR_ARCHIVE}"

    # if includes are used, make sure the test file is saved in one
    TESTRESTORE_FILE=".dar-testrestore-${BACKUP_NAME}-${DATE}"
    OIFS=$IFS
        # loop includes
        IFS=';' read -ra my_array <<< "$INCLUDES"
        for i in "${my_array[@]}"
        do
          TESTRESTORE_FILE="${i}/.dar-testrestore-${BACKUP_NAME}-${DATE}"
          break
        done
    IFS=$OIFS


    if [[ $MODE == "FULL"  ]]; then 
      # backup
      backupTestRestore "$ARCHIVEPATH" "$FS_ROOT" \
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}" "${LOG_LOCATION}"
    else
      PREV=`ls "${MOUNT_POINT}"|grep -P ${BACKUP_NAME}_FULL|grep dar$|tail -n 1`
      NEWEST_ARCHIVE=${PREV%%.*}
      echo NEWEST archive: $NEWEST_ARCHIVE
      # backup
      diffBackupTestRestore "$ARCHIVEPATH" "$FS_ROOT" "${MOUNT_POINT}/$NEWEST_ARCHIVE" \
        "$TESTRESTORE_PATH" "$TESTRESTORE_FILE" "${EXCLUDES}" "${INCLUDES}"  "${LOG_LOCATION}"
    fi
}



# The standard recipe for backing up differentially a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
# $1 "$ARCHIVEPATH" - the full path to the archive (fx /backup/some_archive_date)
# $2 "$FS_ROOT" - take backup of this and below
# $3 "${MOUNT_POINT}/$NEWEST_ARCHIVE" - the newest backup 
# $4 "$TESTRESTORE_PATH" - where to do the restore test
# $5 "$TESTRESTORE_FILE" - the file to restore
# $6 EXCLUDES from conf files
# $7 INCLUDES from conf files
# $8 LOG_LOCATION
diffBackupTestRestore () {
    local DAR_ARCHIVE=`basename "$1"`
    echo "Hej" > "$2/$5"  # create testfile
    darDiffBackup "$1" "$2" "$3" "$6" "$7" "$8"
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        sendDiscordMsg  "dar backup of archive: ${DAR_ARCHIVE}, result: $RESULT"
        darTestBackup "$1" "$4" "$5" 
        RESULT=$?
    else
        sendDiscordMsg  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
    fi
    rm -f "$2/$5"  # remove testfile
    return $RESULT
}



# The standard recipe for backing up a FS_ROOT, test the archive and test restore one file
# this function drives the underlying backup, test and restore functions
# $1 "$ARCHIVEPATH" - the full path to the archive (fx /backup/some_archive_date)
# $2 "$FS_ROOT" - take backup of this and below
# $3 "$TESTRESTORE_PATH" - where to do the restore test
# $4 "$TESTRESTORE_FILE" - the file to restore
# $5 "EXCLUDES" - -P's from config file
# $6 "INCLUDES" - -g's from config file
# $7 LOG_LOCATION
backupTestRestore () {
    local DAR_ARCHIVE=`basename "$1"`
    echo "Hej" > "$2/$4"  # create testfile
    darBackup "$1" "$2" "${5}" "$6" "$7"
    RESULT=$?
    if [[ $RESULT == "0" ]]; then
        sendDiscordMsg  "dar backup of archive: ${DAR_ARCHIVE}, result: $RESULT"
        darTestBackup "$1" "$3" "$4"
        RESULT=$?
    else
        sendDiscordMsg  "dar ERROR: backup of archive: ${DAR_ARCHIVE} failed"
    fi
    rm -f "$2/$4"  # remove testfile
    return $RESULT
}


#
# Make sure that the previous generated backup script in /tmp is deleted
# if it exists, try to delete it, if that fails send a notice and give up
# $1: the file to check
deleteTmpScript () {
    SCRIPT="$1"
    if [[ -f "$SCRIPT" ]]; then
        rm -f "$SCRIPT"
        if [[ $? != "0" ]];then
            log  "== ERROR Could not delete $SCRIPT - exiting"
            sendDiscordMsg  "dar backup NOT run: problem deleting $SCRIPT"
            exit 1
        fi
    fi
}




# do a dar backup
# $1: ARCHIVEPATH, fx ~/mn/dar/dba_2021-06-06
# $2: --fs-root, where to take the backup
# $3: excludes, which directories to exclude, from the conf file
# $4: includes, which directories to back up, from the conf file
# $5: LOG_LOCATION
darBackup () {
    log "========================"
    log "Start dar backup of: $2"
    log "========================"

    OIFS=$IFS
        # build excludes 
        IFS=';' read -ra my_array <<< "$3"
        local excludes=
        for i in "${my_array[@]}"
        do
            excludes+=" -P "
            excludes+="\"$i\"" 
        done

        # build includes
        IFS=';' read -ra my_array <<< "$4"
        local includes=
        for i in "${my_array[@]}"
        do
            includes+=" -g "
            includes+="\"$i\"" 
        done
    IFS=$OIFS

    SCRIPT=/tmp/dar-full-backup.sh
    deleteTmpScript "$SCRIPT"

    echo "dar -vf \
        -c \"$1\" \
        -N \
        -B \"${SCRIPTDIRPATH}/../conf/darrc\" \
        --fs-root \"$2\" \
        $includes \
        $excludes \
        --slice 4G \
        --compression lzo:5 \
        --empty-dir \
        par2 \
        compress-exclusion  2>&1 | tee -a ${5}/dar-backup.log" > "$SCRIPT"

    chmod +x "$SCRIPT"
    "$SCRIPT"

}


# do a dar differential backup
# $1: ARCHIVEPATH, fx ~/mn/dar/dba_2021-06-06
# $2: --fs-root, where to take the backup
# $3: the archive to do the diff against (the -A option)
# $4: excludes from conf files
# $5: includes from conf files
# $6: LOG_LOCATION
darDiffBackup () {
    log "== Start dar diff backup of: $2, diff against: $3"

    OIFS=$IFS
        # build excludes 
        IFS=';' read -ra my_array <<< "$4"
        local excludes=
        for i in "${my_array[@]}"
        do
            excludes+=" -P "
            excludes+="\"$i\"" 
        done

        # build includes
        IFS=';' read -ra my_array <<< "$5"
        local includes=
        for i in "${my_array[@]}"
        do
            includes+=" -g "
            includes+="\"$i\"" 
        done
    IFS=$OIFS

    SCRIPT=/tmp/dar-diff-backup.sh
    deleteTmpScript "$SCRIPT"

    echo "dar -vf \
        -c \"$1\" \
        -N \
        -B \"${SCRIPTDIRPATH}/../conf/darrc\" \
        --fs-root \"$2\" \
        $includes \
        $excludes \
         -A \"$3\" \
        --slice 4G \
        --compression lzo:5 \
        --empty-dir \
        par2 \
        compress-exclusion  2>&1 | tee -a ${6}/dar-backup.log" > "$SCRIPT"

    chmod +x "$SCRIPT"
    "$SCRIPT"


}


# test a dar backup
# $1: dar archive path
# $2: the path to restore dir
# $3: file to restore
darTestBackup () {
  # test the backup
  local ARCHIVE=`basename "$1"`
  log  "== Test dar archive: $1"
  dar -vd \
      -t "$1"
  RESULT=$?
  sendDiscordMsg "dar test af archive: $ARCHIVE, result: $RESULT"

  # restore the test file
  log "== Test restore of  file: $3"
  rm -f "$2/$3" # make sure the file is not there....
  dar -vd \
      -w \
      -x "$1" \
      -R "$2" \
      -g "$3"
  RESULT=$?
  if [[ $RESULT == "0" ]]; then
    if [[ -f "$2/$3"  ]]; then
        sendDiscordMsg  "dar Restore Test af archive: $ARCHIVE, result: $RESULT"
    else
        sendDiscordMsg  "dar ERROR: did not restore test file: $3 from archive: $ARCHIVE"
    fi
  else
    sendDiscordMsg  "dar ERROR:  restore Test af archive: $ARCHIVE, result: $RESULT"
  fi
  rm -f "$2/$3" # remove the test file
  return $RESULT
}