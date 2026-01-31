
import subprocess
import os
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import psutil
import random
import time
import shutil
import signal
import tempfile

from dar_backup.command_runner import CommandRunner
from dar_backup.util import CommandResult

from tests.envdata import EnvData
import hashlib







DISK_IMG = "testdisk.img"
DISK_SIZE_MB = 10
PID_FILE = "guestmount.pid"



def guest_unmount(env: EnvData, pid, img_path):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
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
        result: CommandResult =  runner.run(command)

        command = ['cat', script_path]
        result: CommandResult =  runner.run(command)
           
    except:
        assert False, "guest unmount failed"
    finally:
        command = ['bash', '-c', script_path]
        result: CommandResult =  runner.run(command)
        if result.returncode == 0:
            env.logger.info(f"guestunmount of: '{env.data_dir}' succeeded")
        else:
            command = ['bash', '-c', script_path]
            result: CommandResult =  runner.run(command)

            if result.returncode == 0:
                env.logger.info(f"guestunmount of: '{env.data_dir}' succeeded")
            else:
                command = ['umount', '-l', env.data_dir]
                result: CommandResult =  runner.run(command)

        #os.remove(img_path)
        os.remove(script_path)


def mount(env: EnvData):
        runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
        pid_path = os.path.join(env.test_dir, PID_FILE)
        img_path = os.path.join(env.test_dir, DISK_IMG)

        command = ["guestmount", "-a", f"{img_path}", "--pid-file", f"{pid_path}", "-m", "/dev/sda", f"{env.data_dir}"]
        result: CommandResult = runner.run(command)
        assert result.returncode == 0, "guestmount failed"

        with open(pid_path, "r") as f:
            pid = f.read()
        env.logger.info(f"guestmount PID: {pid}")

        return pid


@pytest.fixture(scope="function")
def guestmount_disk(env: EnvData):
    try:
        runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
        
        #pid_path = os.path.join(env.test_dir, PID_FILE)
        img_path = os.path.join(env.test_dir, DISK_IMG)

        # sanity check
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sh") as tmpfile:
            tmpfile.write( f"df | grep {env.data_dir}")
            script_path = tmpfile.name  
        os.chmod(script_path, 0o700)
        command = ['bash', '-c', script_path]
        result: CommandResult =  runner.run(command)
        assert not result.returncode == 0, f'an image is already mounted on: f"{img_path}", failing test'

        # make sure the directory is empty, otherwise guestmount fails
        shutil.rmtree(env.data_dir)
        os.makedirs(env.data_dir)

        command = ['dd', 'if=/dev/zero', f"of={img_path}", 'bs=1M', f"count={DISK_SIZE_MB}"]
        result:CommandResult = runner.run(command)
        assert result.returncode == 0, f'dd: f"{img_path}" failed'

        command = ['mkfs.ext4', f"{img_path}"]
        result:CommandResult = runner.run(command)
        assert result.returncode == 0, f'mkfs.ext4 in: f"{img_path}" failed'
        
        pid = mount(env)

        # Populate disk with files to make backup take some time
        for i in range(60):
            fname = os.path.join(env.data_dir, f"file_{i}.txt")
            with open(fname, "w") as f:
                f.write("Hello pytest!\n" * 5000)

        command = ["sync"]
        result: CommandResult = runner.run(command)
        assert result.returncode == 0, "generating test data in guest file system failed"

    except Exception as e:
        env.logger.error(e)
        guest_unmount(env, pid, img_path)
        assert False, "exception happened" 

    yield pid, img_path

    # pid may have changed
    pid_path = os.path.join(env.test_dir, PID_FILE)
    with open(pid_path, "r") as f:
        pid = f.read()
    env.logger.info(f"guestmount PID: {pid}")

    guest_unmount(env, pid, img_path)

    
def xtest_verify_guestmount_is_working(setup_environment, env: EnvData, guestmount_disk):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ["ls", "-l", f"{env.data_dir}"]
    runner.run(command)

    start = time.perf_counter()
    command = ['dar-backup', '-F', '-d', "example", '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    runner.run(command)
    end = time.perf_counter()
    env.logger.info(f"FULL backup took: {end - start:.4f} seconds")


def xtest_corrupt_unmounted_img_file(setup_environment, env: EnvData, guestmount_disk):
    """"
    try to corrupt the img file, while it is unmounted
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    
    pid, img_path = guestmount_disk

    #unmount before corruption
    guest_unmount(env, pid, img_path)
    corrupt_disk_image(img_path, env)

    # mount the now corrupted image
    pid = mount(env)

    start = time.perf_counter()
    command = ['dar-backup', '-F', '-d', "example", '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    runner.run(command)
    end = time.perf_counter()
    env.logger.info(f"FULL backup took: {end - start:.4f} seconds")



def calculate_sha256(img_file: str) -> str:
    """Calculate SHA256 of the image file."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    sha256_hash = hashlib.sha256()
    with open(img_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def number_of_handles(path: str) -> int:
    """
    Determine the number of file handles on a file
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    count = 0
    for proc in psutil.process_iter(['pid', 'name', 'open_files']):
        try:
            if proc.info['open_files']:
                for f in proc.info['open_files']:
                    if f.path == path:
                        count += 1
                        print(f"Process {proc.info['name']} (PID {proc.info['pid']}) has the file open: {f.path}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return count



def corrupt_disk_image(img_file: str, env: EnvData, num_corruptions=40, corruption_size=65536):
    """In-place disk image corruption."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    env.logger.info(f"image file to corrupt: {img_file}")
    if not os.path.exists(img_file):
        assert False, f"image: {img_file} does not exist"

    if not img_file.startswith("/tmp/"):
        assert False, "img path does not start with /tmp/"

    img_sha256 = calculate_sha256(img_file)
    env.logger.info(f"SHA256 of the image file before corruption: {img_sha256}")

    env.logger.info(f"Number of file handles on image file: {number_of_handles(img_file)}")

    # ext4 superblock corruption
    with open(img_file, 'r+b') as f:
        f.seek(1024)
        f.write(os.urandom(1024))
    env.logger.info("[+] Superblock corrupted at offset 1024, size 1024 bytes.")

    rng = random.Random(0)
    with open(img_file, 'r+b') as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        for _ in range(num_corruptions):
            pos = rng.randint(0, size - corruption_size)
            f.seek(pos)
            f.write(os.urandom(corruption_size))
            env.logger.info(f"Corruption at position: {pos}, size: {corruption_size}")
    env.logger.info(f"[+] Corrupted {img_file} at {num_corruptions} locations.")

    img_sha256 = calculate_sha256(img_file)
    env.logger.info(f"SHA256 of the image file after corruption: {img_sha256}")

    env.logger.info(f"Number of file handles on image file: {number_of_handles(img_file)}")


    command = ['sync']
    runner.run(command)
    runner.run(command)
    


def corrupt_superblock(img_file, offset=1024, corruption_size=1024):
    """Specifically corrupts the ext filesystem superblock."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    with open(img_file, 'r+b') as f:
        f.seek(offset)
        f.write(os.urandom(corruption_size))
    print(f"[+] Superblock corrupted at offset {offset}, size {corruption_size} bytes.")




def xtest_dar_backup_with_live_corruption(guestmount_disk):
    backup_name = os.path.join(BACKUP_DIR, "test_backup")
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

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

    # Allow dar to start backing up (avoid fixed sleeps in tests)

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
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    backup_name = os.path.join(BACKUP_DIR, "superblock_backup")

    # Start dar backup
    backup_cmd = f"dar -c {backup_name} -R {guestmount_disk}"
    backup_proc = subprocess.Popen(backup_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)

    # Allow backup to start (avoid fixed sleeps in tests)

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
