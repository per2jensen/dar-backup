import os
import subprocess
import shutil
import filecmp
import pytest


@pytest.fixture
def script_path():
    return os.path.join(os.getcwd(), "src/misc/duplicate2format.py")


@pytest.fixture
def create_sample_src(tmp_path):
    # Create a small src/ structure with 1-3 files
    src = tmp_path / "src"
    src.mkdir()
    (src / "file1.py").write_text("def foo():\n    print( 'hello' )\n")
    (src / "file2.py").write_text("def bar():\n  print('world')\n")
    (src / "file3.py").write_text("# empty file\n")
    return src


def test_no_changes_to_src(create_sample_src, tmp_path, script_path):
    dest = tmp_path / "formatted"
    # Copy original src to a known good backup
    backup_src = tmp_path / "backup"
    shutil.copytree(create_sample_src, backup_src)

    # Run script
    subprocess.run(
        [
            "python3",
            script_path,
            "--src",
            str(create_sample_src),
            "--dest",
            str(dest),
        ],
        check=True,
    )

    # Verify src is unchanged (compare to backup)
    comparison = filecmp.dircmp(str(create_sample_src), str(backup_src))
    assert not comparison.diff_files, "Source files were modified!"


def test_exit_if_dest_exists(create_sample_src, tmp_path, script_path):
    dest = tmp_path / "formatted"
    dest.mkdir()  # Pre-create dest directory

    result = subprocess.run(
        [
            "python3",
            script_path,
            "--src",
            str(create_sample_src),
            "--dest",
            str(dest),
        ],
        capture_output=True,
        text=True,
    )

    assert "already exists" in result.stdout
    assert result.returncode != 0


def test_black_found_or_fail(tmp_path, create_sample_src, script_path):
    dest = tmp_path / "formatted"

    # Manipulate PATH so black is NOT found
    env = os.environ.copy()

    # Locate black
    black_path = shutil.which("black")
    if not black_path:
        pytest.skip("Black is not installed, skipping test.")

    # Rename black binary to simulate it missing
    backup_path = black_path + ".bak"
    os.rename(black_path, backup_path)

    try:
        result = subprocess.run(
            [
                "python3",
                script_path,
                "--src",
                str(create_sample_src),
                "--dest",
                str(dest),
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        # Should fail with FileNotFoundError
        assert result.returncode != 0
        assert "No such file or directory" in result.stderr
    finally:
        # Restore black binary
        os.rename(backup_path, black_path)




def test_black_fixes_format(tmp_path, script_path):
    # Create a small src dir with a known bad format
    src = tmp_path / "src"
    src.mkdir()
    file = src / "bad_format.py"
    file.write_text("def foo( ):\n print( 'bad' )\n")

    dest = tmp_path / "formatted"

    subprocess.run(
        [
            "python3",
            script_path,
            "--src",
            str(src),
            "--dest",
            str(dest),
        ],
        check=True,
    )

    # Read formatted file
    formatted_file = dest / "bad_format.py"
    content = formatted_file.read_text()
    # Should be nicely formatted (no extra spaces)
    assert "def foo():" in content
    assert "print(\"bad\")" in content or "print('bad')" in content


def test_default_dest_handling(tmp_path, script_path):
    # Create a small src dir
    src = tmp_path / "src"
    src.mkdir()
    (src / "file.py").write_text("def a():\n print('a')\n")

    # Create default dest (src-formatted) to trigger exit
    dest = tmp_path / "src-formatted"
    dest.mkdir()

    result = subprocess.run(
        [
            "python3",
            script_path,
            "--src",
            str(src),
        ],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    assert "already exists" in result.stdout
    assert result.returncode != 0
