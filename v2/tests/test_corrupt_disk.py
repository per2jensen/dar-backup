"""
sudo apt install libguestfs-tools



.
├── backups
├── data
│   ├── testdisk.img
│   └── mnt
└── tests
    └── test_live_corruption.py

    
Notes:
On Ubuntu the kernel image has permissions 0o400, so a user cannot read it

Fix:
https://unix.stackexchange.com/questions/437984/why-isnt-the-linux-kernel-image-read-only-by-default


sudo bash -c "cat > /etc/kernel/postinst.d/statoverride << 'EOF'
#!/bin/sh
version=\"\$1\" # passing the kernel version is required 
[ -z \"\${version}\" ] && exit 0
dpkg-statoverride --update --add root root 0644 /boot/vmlinuz-\${version}
EOF"

sudo chmod +x /etc/kernel/postinst.d/statoverride



cleanup function for trapping errors and unmounting the disk image:
=======================================================================

guestmount_cleanup() {
    echo "Cleaning up..."
    # Check if the mount point is active using mountpoint command
    if mountpoint -q "${MNT}"; then
        echo "Mount point '${MNT}' is active. Attempting to unmount using guestunmount..."
        if guestunmount "${MNT}"; then
            echo "Successfully unmounted '${MNT}' with guestunmount."
        else
            echo "guestunmount failed. Attempting lazy unmount..."
            if umount -l "${MNT}"; then
                echo "Successfully unmounted '${MNT}' using lazy unmount."
            else
                echo "Failed to unmount '${MNT}'. Please check MANUALLY."
            fi
        fi
    else
        echo "Mount point '${MNT}' is not mounted."
    fi

    # Remove the PID file if it exists
    if [ -f "${PID}" ]; then
        if rm -f "${PID}"; then
            echo "PID file '${PID}' removed."
        else
            echo "Failed to remove PID file '${PID}'."
        fi
    fi
}


Mount:
========
set -e
set -o pipeail 

IMG=~/tmp/disk.img
PID=/tmp/guestmount_dar-backup_test.pid
MNT=~/tmp/mnt
IMG_SIZE_MB=20

mount |grep -q "$MNT" && echo "Image: \'${IMG}\' already mounted on: \'${MNT}\'" && exit 1

mkdir -p "${MNT}"

dd if=/dev/zero of="${IMG}" bs=1M count="${IMG_SIZE_MB}"  || { echo "Failed to create image: ${IMG}"; exit 1; }

mkfs.ext4 "${IMG}"  || { echo "Failed to create filesystem on: ${IMG}"; exit 1; }

guestmount -a "${IMG}" --pid-file "${PID}" -m /dev/sda "${MNT}"  || { echo "Failed to mount image: ${IMG}"; exit 1; }

pid="$(cat "${PID}")"
echo "guestmount started with PID: ${pid}"

trap guestmount_cleanup ERR


Unmount:
========
guestunmount "${MNT}"
timeout=10
count=$timeout
while [ $count -gt 0 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    sleep 1
    ((count--))
done
if [ $count -gt 0 ]; then
    rm -f "${PID}" || echo "Unmount succeeded, PID file removal failed"
else
    echo "$0: wait for guestmount to exit. Unmount failed after $timeout seconds"
    exit 1
fi

"""

import pytest
import subprocess
import os
import random
import time
import signal

DISK_IMG = "data/testdisk.img"
MOUNT_POINT = "data/mnt"
BACKUP_DIR = "backups"
DISK_SIZE_MB = 100

@pytest.fixture(scope="module")
def guestmount_disk():
    os.makedirs("data", exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    subprocess.run(f"dd if=/dev/zero of={DISK_IMG} bs=1M count={DISK_SIZE_MB}", shell=True, check=True)
    subprocess.run(f"mkfs.ext4 {DISK_IMG}", shell=True, check=True)
    os.makedirs(MOUNT_POINT, exist_ok=True)
    subprocess.run(f"guestmount -a {DISK_IMG} -m /dev/sda {MOUNT_POINT}", shell=True, check=True)

    # Populate disk with files to make backup take some time
    for i in range(50):
        fname = os.path.join(MOUNT_POINT, f"file_{i}.txt")
        with open(fname, "w") as f:
            f.write("Hello pytest!\n" * 5000)
    subprocess.run("sync", shell=True)

    yield MOUNT_POINT

    subprocess.run(f"guestunmount {MOUNT_POINT}", shell=True, check=True)
    os.remove(DISK_IMG)

def corrupt_superblock(img_file, offset=1024, corruption_size=1024):
    """Specifically corrupts the ext filesystem superblock."""
    with open(img_file, 'r+b') as f:
        f.seek(offset)
        f.write(os.urandom(corruption_size))
    print(f"[+] Superblock corrupted at offset {offset}, size {corruption_size} bytes.")


def corrupt_disk_image(img_file, num_corruptions=10, corruption_size=4096):
    """In-place disk image corruption."""
    with open(img_file, 'r+b') as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        for _ in range(num_corruptions):
            pos = random.randint(0, size - corruption_size)
            f.seek(pos)
            f.write(os.urandom(corruption_size))
    print(f"[+] Corrupted {img_file} at {num_corruptions} locations.")


def test_dar_backup_with_live_corruption(guestmount_disk):
    backup_name = os.path.join(BACKUP_DIR, "test_backup")

    # Start dar backup as a subprocess
    backup_cmd = f"dar -c {backup_name} -R {guestmount_disk}"
    print(f"[+] Starting backup: {backup_cmd}")

    backup_proc = subprocess.Popen(
        backup_cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )

    # Wait some seconds to ensure dar starts backing up
    time.sleep(3)

    # Corrupt the disk image while backup runs
    print("[+] Corrupting disk image live during backup")
    corrupt_disk_image(DISK_IMG)

    # Wait for backup to finish (with timeout)
    try:
        stdout, stderr = backup_proc.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        print("[!] Backup took too long, terminating.")
        os.killpg(os.getpgid(backup_proc.pid), signal.SIGTERM)
        pytest.fail("Backup timeout after corruption")

    print(f"[+] Backup stdout: {stdout.decode()}")
    print(f"[+] Backup stderr: {stderr.decode()}")

    # Assert that dar detected corruption or errors
    backup_output = (stdout + stderr).decode().lower()
    assert "error" in backup_output or backup_proc.returncode != 0, \
        "Backup did not detect corruption!"

def test_dar_with_superblock_corruption(guestmount_disk):
    backup_name = os.path.join(BACKUP_DIR, "superblock_backup")

    # Start dar backup
    backup_cmd = f"dar -c {backup_name} -R {guestmount_disk}"
    backup_proc = subprocess.Popen(backup_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

    # Wait a bit to ensure backup started
    time.sleep(2)

    # Unmount to safely corrupt the superblock
    subprocess.run(f"guestunmount {guestmount_disk}", shell=True, check=True)

    # Corrupt superblock directly
    corrupt_superblock(DISK_IMG)

    # Attempt remount (expected to fail)
    mount_result = subprocess.run(f"guestmount -a {DISK_IMG} -m /dev/sda {MOUNT_POINT}", shell=True)
    if mount_result.returncode != 0:
        print("[+] Mount failed as expected due to superblock corruption.")

    # Wait for dar backup subprocess
    stdout, stderr = backup_proc.communicate(timeout=60)

    print("[dar stdout]:", stdout.decode())
    print("[dar stderr]:", stderr.decode())

    # Verify that dar detected serious issues due to superblock corruption
    backup_output = (stdout + stderr).decode().lower()
    assert "error" in backup_output or backup_proc.returncode != 0, \
        "Backup unexpectedly succeeded despite superblock corruption!"
