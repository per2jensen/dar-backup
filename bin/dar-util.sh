

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
    logger -s "$1"
    curl -i -H "Accept: application/json"  \
        -H "Content-Type:application/json"  \
        -X POST --data "{\"content\": \"$1\"}" \
        https://discord.com/api/webhooks/${DISCORD_WEBHOOK} \
        >/dev/null 2>&1
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
diffBackupTestRestore () {
    local DAR_ARCHIVE=`basename "$1"`
    echo "Hej" > "$2/$5"  # create testfile
    darDiffBackup "$1" "$2" "$3" "$6" "$7"
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
backupTestRestore () {
    local DAR_ARCHIVE=`basename "$1"`
    echo "Hej" > "$2/$4"  # create testfile
    darBackup "$1" "$2" "${5}" "$6"
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




# do a dar backup
# $1: ARCHIVEPATH, fx ~/mn/dar/dba_2021-06-06
# $2: --fs-root, where to take the backup
# $3: excludes, which directories to exclude, from the conf file
# $4: includes, which directories to back up, from the conf file
darBackup () {
    logger -s "Start dar backup of: $2"

    OLIFS=$IFS
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
    if [[ -f "$SCRIPT" ]]; then
        rm -f "$SCRIPT"
        if [[ $? != "0" ]];then
            logger -s "Could not delete $SCRIPT - exiting"
            exit 1
        fi
    fi 
    echo dar -vd \
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
        compress-exclusion > "$SCRIPT"

    chmod +x "$SCRIPT"
    "$SCRIPT"

}


# do a dar differential backup
# $1: ARCHIVEPATH, fx ~/mn/dar/dba_2021-06-06
# $2: --fs-root, where to take the backup
# $3: the archive to do the diff against (the -A option)
# $4: excludes from conf files
# $5: includes from conf files
darDiffBackup () {
    logger -s "Start dar diff backup of: $2, diff against: $3"

    OLIFS=$IFS
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

    if [[ -f "$SCRIPT" ]]; then
        rm -f "$SCRIPT"
        if [[ $? != "0" ]];then
            logger -s "Could not delete $SCRIPT - exiting"
            exit 1
        fi
    fi 

    echo dar -vd \
        -N \
        -B \"${SCRIPTDIRPATH}/../conf/darrc\" \
        -c \"$1\" \
        --fs-root \"$2\" \
        $includes \
        $excludes \
         -A \"$3\" \
        --slice 4G \
        --compression lzo:5 \
        --empty-dir \
        par2 \
        compress-exclusion  > "$SCRIPT"

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
  logger -s "Test dar archive: $1"
  dar -vd \
      -t "$1"
  RESULT=$?
  sendDiscordMsg "dar test af archive: $ARCHIVE, result: $RESULT"

  # restore the test file
  logger -s "Test restore of  file: $3"
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