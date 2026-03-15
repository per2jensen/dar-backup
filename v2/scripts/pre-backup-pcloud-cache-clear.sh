#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This script is part of the per2jensen's `dar-backup`` project.
# The script is intended to be run as a pre-backup hook for dar-backup,
# to mitigate I/O errors caused by the pCloud Linux client's cache when backing up.
#
# Pre-backup script for dar-backup
# Clears the pCloud cache to avoid I/O errors on Crypto Folder files
# caused by corrupt/stale cache blocks in the pCloud Linux FUSE client.
#
# Background: The pCloud Linux client stores its cache in a single large
# sparse file (~/.pcloud/Cache/cached). Stale or corrupt blocks in this
# file cause mid-stream I/O errors when dar tries to read large files
# from the Crypto Folder, resulting in exit code 5 from dar.
#
# Solution: Kill pCloud, clear the cache, restart and wait for the
# Crypto Folder to be accessible before proceeding with the backup.
#
#

CRYPTO_FOLDER="/home/pj/pCloudDrive/Crypto Folder"
PCLOUD_CACHE="$HOME/.pcloud/Cache"
TIMEOUT=60

echo "Pre-backup: stopping pCloud..."
pkill -TERM pcloud

# Wait for pCloud to fully stop and release all file handles
echo "Pre-backup: waiting for pCloud to stop..."
while pgrep pcloud > /dev/null; do
    sleep 1
done

# If pCloud is still running after TERM, force kill it
if pgrep pcloud > /dev/null; then
    echo "Pre-backup: pCloud did not stop gracefully, force killing..."
    pkill -KILL pcloud
    sleep 2
fi

echo "Pre-backup: clearing pCloud cache..."
rm -rf "${PCLOUD_CACHE:?}"/*

echo "Pre-backup: restarting pCloud..."
pcloud &

# Wait until Crypto Folder is accessible, with timeout
echo "Pre-backup: waiting for pCloud Crypto Folder to be accessible..."
ELAPSED=0
until ls "${CRYPTO_FOLDER}/" > /dev/null 2>&1; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ $ELAPSED -ge $TIMEOUT ]; then
        echo "ERROR: pCloud Crypto Folder not accessible after ${TIMEOUT}s - is it unlocked?"
        exit 1
    fi
done

echo "Pre-backup: pCloud ready, proceeding with backup"
exit 0