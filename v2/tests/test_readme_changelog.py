"""Tests for --readme / --changelog CLI options and the doc path resolution they depend on.

Two fixture families:
- dummy_docs   — creates minimal stub files; fast, no shell script dependency.
- real_docs    — runs scripts/copy_docs.sh exactly as build.sh and release.sh do,
                 then verifies _resolve_doc_path() finds real project content.
                 This mirrors the installed-wheel scenario and catches gaps that
                 dummy files cannot.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.component

V2_DIR = Path(__file__).parent.parent
PKG_DIR = V2_DIR / "src" / "dar_backup"


# ── fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def dummy_docs():
    """Minimal stub README.md and Changelog.md in src/dar_backup/."""
    readme    = PKG_DIR / "README.md"
    changelog = PKG_DIR / "Changelog.md"
    readme.write_text("# Dummy README\nSome content here.")
    changelog.write_text("# Dummy Changelog\nSome changes here.")
    yield
    readme.unlink(missing_ok=True)
    changelog.unlink(missing_ok=True)


@pytest.fixture
def real_docs():
    """Copy real project docs via scripts/copy_docs.sh, mirroring build.sh and release.sh.

    Verifies that the installed-package layout is correct: README.md,
    Changelog.md, and doc/*.md land in src/dar_backup/ so _resolve_doc_path()
    can find them the same way a pip-installed wheel would.
    """
    script = V2_DIR / "scripts" / "copy_docs.sh"
    subprocess.run(["bash", str(script)], check=True, cwd=str(V2_DIR))
    yield
    (PKG_DIR / "README.md").unlink(missing_ok=True)
    (PKG_DIR / "Changelog.md").unlink(missing_ok=True)
    shutil.rmtree(PKG_DIR / "doc", ignore_errors=True)


@pytest.fixture(scope="module")
def cli_runner():
    """Run dar_backup as a subprocess and return the CompletedProcess."""
    def run(args, cwd=None):
        return subprocess.run(
            ["python3", "-m", "dar_backup.dar_backup", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    return run


# ── dummy-docs tests (fast path) ──────────────────────────────────────────────

@pytest.mark.parametrize("option", ["--readme", "--readme-pretty", "--changelog", "--changelog-pretty"])
def test_help_options_exit_zero_with_dummy_docs(cli_runner, dummy_docs, option):
    """All four doc options must exit 0 and produce non-empty output."""
    result = cli_runner([option])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


@pytest.mark.parametrize("option", ["--readme", "--changelog"])
def test_plain_output_contains_dummy_headers(cli_runner, dummy_docs, option):
    """Plain (non-pretty) output must echo the stub file content."""
    result = cli_runner([option])
    assert result.returncode == 0
    assert "Dummy" in result.stdout


# ── real-docs tests (mirrors installed-wheel scenario) ────────────────────────

def test_copy_docs_script_creates_readme(real_docs):
    """scripts/copy_docs.sh must place README.md in src/dar_backup/."""
    assert (PKG_DIR / "README.md").exists(), "README.md missing after copy_docs.sh"


def test_copy_docs_script_creates_changelog(real_docs):
    """scripts/copy_docs.sh must place Changelog.md in src/dar_backup/."""
    assert (PKG_DIR / "Changelog.md").exists(), "Changelog.md missing after copy_docs.sh"


def test_copy_docs_script_creates_doc_dir(real_docs):
    """scripts/copy_docs.sh must populate src/dar_backup/doc/ with at least one .md file."""
    doc_dir = PKG_DIR / "doc"
    assert doc_dir.is_dir(), "src/dar_backup/doc/ not created by copy_docs.sh"
    assert any(doc_dir.glob("*.md")), "src/dar_backup/doc/ contains no .md files"


# Internal files that must never ship in the package.
_EXCLUDED_DOCS = {
    "todo.md",
    "dev.md",
    "dar_manager_w_dst_bug_report.md",
    "NFS server notes.md",
}

def test_copy_docs_excludes_internal_files(real_docs):
    """Internal/developer-only docs must not be present in src/dar_backup/doc/."""
    doc_dir = PKG_DIR / "doc"
    for name in _EXCLUDED_DOCS:
        assert not (doc_dir / name).exists(), (
            f"{name} is an internal doc and must not be shipped in the package"
        )


def test_copy_docs_includes_all_user_facing_files(real_docs):
    """Every doc/*.md not in the exclusion list must be present in src/dar_backup/doc/.

    Derived dynamically from the source doc/ directory so new files are
    automatically covered without updating this test.
    """
    expected = {
        p.name for p in (V2_DIR / "doc").glob("*.md")
        if p.name not in _EXCLUDED_DOCS
    }
    assert expected, "No user-facing docs found in doc/ — check V2_DIR"
    doc_dir = PKG_DIR / "doc"
    for name in expected:
        assert (doc_dir / name).exists(), (
            f"{name} is a user-facing doc and must be shipped in the package"
        )


def test_resolve_doc_path_finds_real_readme(real_docs):
    """_resolve_doc_path must resolve README.md to the package dir after copy_docs.sh."""
    from dar_backup.dar_backup import _resolve_doc_path
    path = _resolve_doc_path(None, "README.md")
    assert path.exists(), f"_resolve_doc_path returned non-existent path: {path}"
    content = path.read_text()
    assert "dar-backup" in content.lower(), (
        f"README.md at {path} does not contain real project content"
    )


def test_resolve_doc_path_finds_real_changelog(real_docs):
    """_resolve_doc_path must resolve Changelog.md to the package dir after copy_docs.sh."""
    from dar_backup.dar_backup import _resolve_doc_path
    path = _resolve_doc_path(None, "Changelog.md")
    assert path.exists(), f"_resolve_doc_path returned non-existent path: {path}"
    content = path.read_text()
    assert "dar-backup" in content.lower(), (
        f"Changelog.md at {path} does not contain real project content"
    )


@pytest.mark.parametrize("option", ["--readme", "--readme-pretty", "--changelog", "--changelog-pretty"])
def test_help_options_exit_zero_with_real_docs(cli_runner, real_docs, option):
    """All four doc options must exit 0 with real content present."""
    result = cli_runner([option])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


@pytest.mark.parametrize("option", ["--readme", "--changelog"])
def test_plain_output_contains_real_content(cli_runner, real_docs, option):
    """Plain output must contain real project content, not stub text."""
    result = cli_runner([option])
    assert result.returncode == 0
    assert "dar-backup" in result.stdout.lower()
    assert "Dummy" not in result.stdout


# ── --doc / --doc-pretty tests ───────────────────────────────────────────────

def test_doc_prints_existing_file(cli_runner, real_docs):
    """--doc <name> must print the doc file content and exit 0."""
    result = cli_runner(["--doc", "getting-started"])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_doc_pretty_prints_existing_file(cli_runner, real_docs):
    """--doc-pretty <name> must print rendered content and exit 0."""
    result = cli_runner(["--doc-pretty", "getting-started"])
    assert result.returncode == 0
    assert result.stdout.strip() != ""


def test_doc_output_contains_real_content(cli_runner, real_docs):
    """--doc output must contain content from the real doc file."""
    result = cli_runner(["--doc", "restoring"])
    assert result.returncode == 0
    assert "dar-backup" in result.stdout.lower()


def test_doc_unknown_name_exits_nonzero(cli_runner, real_docs):
    """--doc with an unknown name must exit non-zero and mention the name."""
    result = cli_runner(["--doc", "no-such-document"])
    assert result.returncode != 0
    assert "no-such-document" in result.stderr


def test_doc_unknown_name_lists_available(cli_runner, real_docs):
    """--doc with an unknown name must list available doc names on stderr."""
    result = cli_runner(["--doc", "no-such-document"])
    assert result.returncode != 0
    assert "getting-started" in result.stderr


def test_doc_completer_returns_all_docs(real_docs):
    """_doc_completer with empty prefix must return all available doc names."""
    from dar_backup.dar_backup import _doc_completer
    names = _doc_completer("")
    assert len(names) > 0
    assert "getting-started" in names
    assert "restoring" in names


def test_doc_completer_filters_by_prefix(real_docs):
    """_doc_completer must filter by prefix."""
    from dar_backup.dar_backup import _doc_completer
    names = _doc_completer("get")
    assert all(n.startswith("get") for n in names)
    assert "getting-started" in names


def test_doc_completer_excludes_internal_files(real_docs):
    """_doc_completer must not return names of excluded internal docs."""
    from dar_backup.dar_backup import _doc_completer
    names = _doc_completer("")
    assert "todo" not in names
    assert "dev" not in names


# ── missing-file tests ────────────────────────────────────────────────────────

@pytest.mark.parametrize("option", ["--readme", "--readme-pretty"])
def test_readme_missing_exits_nonzero(option, tmp_path):
    """--readme must exit non-zero when README.md cannot be found."""
    stub = tmp_path / "stub.py"
    stub.write_text(
        "import sys\nfrom pathlib import Path\n"
        "p = Path(__file__).parent / 'README.md'\n"
        "if not p.exists(): sys.exit(1)\nprint(p.read_text())\n"
    )
    result = subprocess.run(["python3", str(stub), option], capture_output=True, text=True)
    assert result.returncode != 0


@pytest.mark.parametrize("option", ["--changelog", "--changelog-pretty"])
def test_changelog_missing_exits_nonzero(option, tmp_path):
    """--changelog must exit non-zero when Changelog.md cannot be found."""
    stub = tmp_path / "stub.py"
    stub.write_text(
        "import sys\nfrom pathlib import Path\n"
        "p = Path(__file__).parent / 'Changelog.md'\n"
        "if not p.exists(): sys.exit(1)\nprint(p.read_text())\n"
    )
    result = subprocess.run(["python3", str(stub), option], capture_output=True, text=True)
    assert result.returncode != 0
