
import pytest
import subprocess
import os
import random
import time
import shutil
import signal
import tempfile

from dar_backup.util import run_command
from dar_backup.util import CommandResult


DISK_IMG = "testdisk.img"
DISK_SIZE_MB = 10
PID_FILE = "guestmount.pid"



def guest_unmount(env, pid, img_path):
    try:
        unmount_script=f"""
    guestunmount "{env.data_dir}"
    count=10
    while [ $count -gt 0 ]; do
        if ! kill -0 "{pid}" 2>/dev/null; then
            break
        fi
        sleep 1
        ((count--))
    done
    if [ $count -gt 0 ]; then
        echo "Unmount succeeded"
        exit 0
    else
        echo "$0: wait for guestmount to exit. Unmount failed after $timeout seconds"
        exit 1
    fi
    """

        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sh") as tmpfile:
            tmpfile.write(unmount_script)
            script_path = tmpfile.name

        os.chmod(script_path, 0o700)

        command = ['ls', '-l', script_path]
        result: CommandResult =  run_command(command)

        command = ['cat', script_path]
        result: CommandResult =  run_command(command)
           
    except:
        assert False, "guest unmount failed"
    finally:
        command = ['bash', '-c', script_path]
        result: CommandResult =  run_command(command)
        if result.returncode == 0:
            env.logger.info(f"guestunmount of: '{env.data_dir}' succeeded")
        else:
            time.sleep(5)
            command = ['bash', '-c', script_path]
            result: CommandResult =  run_command(command)

            if result.returncode == 0:
                env.logger.info(f"guestunmount of: '{env.data_dir}' succeeded")
            else:
                time.sleep(5)
                command = ['umount', '-l', env.data_dir]
                result: CommandResult =  run_command(command)

        os.remove(img_path)
        os.remove(script_path)



@pytest.fixture(scope="function")
def guestmount_disk(env):
    try:
        img_path = os.path.join(env.test_dir, DISK_IMG)
        pid_path = os.path.join(env.test_dir, PID_FILE)

        # sanity check
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sh") as tmpfile:
            tmpfile.write( f"df | grep {env.data_dir}")
            script_path = tmpfile.name  
        os.chmod(script_path, 0o700)
        command = ['bash', '-c', script_path]
        result: CommandResult =  run_command(command)
        assert not result.returncode == 0, f'an image is already mounted on: f"{img_path}", failing test'

        # make sure the directory is empty, otherwise guestmount fails
        shutil.rmtree(env.data_dir)
        os.makedirs(env.data_dir)

        command = ['dd', 'if=/dev/zero', f"of={img_path}", 'bs=1M', f"count={DISK_SIZE_MB}"]
        result:CommandResult = run_command(command)
        assert result.returncode == 0, f'dd: f"{img_path}" failed'

        command = ['mkfs.ext4', f"{img_path}"]
        result:CommandResult = run_command(command)
        assert result.returncode == 0, f'mkfs.ext4 in: f"{img_path}" failed'
        
        command = ["guestmount", "-a", f"{img_path}", "--pid-file", f"{pid_path}", "-m", "/dev/sda", f"{env.data_dir}"]
        result: CommandResult = run_command(command)
        assert result.returncode == 0, "guestmount failed"

        with open(pid_path, "r") as f:
            pid = f.read()
        env.logger.info(f"guestmount PID: {pid}")

        # Populate disk with files to make backup take some time
        for i in range(60):
            fname = os.path.join(env.data_dir, f"file_{i}.txt")
            with open(fname, "w") as f:
                f.write("Hello pytest!\n" * 5000)

        command = ["sync"]
        result: CommandResult = run_command(command)
        assert result.returncode == 0, "generating test data in guest file system failed"

    except Exception as e:
        env.logger.error(e)
        guest_unmount(env, pid, img_path)

    yield

    guest_unmount(env, pid, img_path)

    
def test_verify_guestmount_is_working(setup_environment, env, guestmount_disk):

    command = ["ls", "-l", f"{env.data_dir}"]
    run_command(command)

    start = time.perf_counter()
    command = ['dar-backup', '-F', '-d', "example", '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    run_command(command)
    end = time.perf_counter()
    env.logger.info(f"FULL backup took: {end - start:.4f} seconds")


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



def xtest_dar_backup_with_live_corruption(guestmount_disk):
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


def xtest_dar_with_superblock_corruption(guestmount_disk):
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
