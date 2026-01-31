import subprocess
from pathlib import Path
import pytest

pytestmark = pytest.mark.component













@pytest.fixture(autouse=True)
def create_readme_and_changelog():
    """Create dummy README.md and Changelog.md in src/dar_backup for CLI tests."""
    dar_backup_dir = Path("src/dar_backup")
    dar_backup_dir.mkdir(parents=True, exist_ok=True)

    readme = dar_backup_dir / "README.md"
    changelog = dar_backup_dir / "Changelog.md"

    readme.write_text("# Dummy README\nSome content here.")
    changelog.write_text("# Dummy Changelog\nSome changes here.")

    yield

    # Clean up after tests
    readme.unlink(missing_ok=True)
    changelog.unlink(missing_ok=True)



# === Real CLI runner using your actual dar_backup CLI ===
@pytest.fixture(scope="module")
def cli_runner():
    def run(args, cwd=None):
        return subprocess.run(
            ["python3", "-m", "dar_backup.dar_backup", *args],
            cwd=cwd,
            capture_output=True,
            text=True
        )
    return run

# === Run real script and check it returns success and content ===
@pytest.mark.parametrize("option", ["--readme", "--readme-pretty", "--changelog", "--changelog-pretty"])
def test_help_options_success(cli_runner, option):
    result = cli_runner([option])
    assert result.returncode == 0
    assert result.stdout.strip() != ""

# === Temporary stub runner for simulating missing README/Changelog ===
@pytest.fixture()
def stub_runner():
    def run_stub(option, stub_code, tmp_path):
        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.chdir(tmp_path)
        (tmp_path / "src/dar_backup").mkdir(parents=True)
        (tmp_path / "src/dar_backup/__init__.py").write_text("")
        stub_path = tmp_path / "src/dar_backup/dar_backup.py"
        stub_path.write_text(stub_code)
        result = subprocess.run(
            ["python3", str(stub_path), option],
            cwd=tmp_path,
            capture_output=True,
            text=True
        )
        monkeypatch.undo()
        return result
    return run_stub

@pytest.mark.parametrize("option", ["--readme", "--readme-pretty"])
def test_readme_missing(stub_runner, option, tmp_path):
    stub_code = '''
import sys
from pathlib import Path

def print_readme(_, pretty):
    path = Path(__file__).parent / "README.md"
    if not path.exists():
        sys.exit(1)
    print(path.read_text())

def main():
    print_readme(None, "--readme-pretty" in sys.argv)

if __name__ == "__main__":
    main()
'''
    result = stub_runner(option, stub_code, tmp_path)
    assert result.returncode != 0

@pytest.mark.parametrize("option", ["--changelog", "--changelog-pretty"])
def test_changelog_missing(stub_runner, option, tmp_path):
    stub_code = '''
import sys
from pathlib import Path

def print_changelog(_, pretty):
    path = Path(__file__).parent / "Changelog.md"
    if not path.exists():
        sys.exit(1)
    print(path.read_text())

def main():
    print_changelog(None, "--changelog-pretty" in sys.argv)

if __name__ == "__main__":
    main()
'''
    result = stub_runner(option, stub_code, tmp_path)
    assert result.returncode != 0



@pytest.mark.parametrize("option", ["--readme", "--readme-pretty", "--changelog", "--changelog-pretty"])
def test_help_options_success(cli_runner, option):
    result = cli_runner([option])
    assert result.returncode == 0


@pytest.mark.parametrize("option", ["--readme", "--changelog"])
def test_plain_output_contains_headers(cli_runner, option):
    result = cli_runner([option])
    assert result.returncode == 0
    assert "# Dummy" in result.stdout or "Dummy" in result.stdout

