# tests/test_demo.py
import sys
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import dar_backup.demo as demo
import pytest

pytestmark = pytest.mark.unit









def _ns(**kw):
    # Defaults that demo.main() may reference
    base = dict(
        install=False,
        generate=False,
        cleanup=False,
        override=False,
        root_dir=None,
        dir_to_backup=None,
        backup_dir=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


# 1) No args -> prints help and exits 1
def test_demo_help_no_args(capsys, monkeypatch):
    monkeypatch.setenv("PYTHONWARNINGS", "ignore")  # keep output clean
    monkeypatch.setattr(sys, "argv", ["demo"])
    with pytest.raises(SystemExit) as ex:
        demo.main()
    assert ex.value.code == 1
    out = capsys.readouterr().out
    assert "Set up demo configuration" in out or "usage:" in out.lower()


# 2) --generate -> calls generate_file twice with hardcoded /tmp targets
def test_demo_generate_calls_generate_file(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["demo", "--generate"])

    calls = []

    def fake_generate_file(args, template, outpath, vars_map, opts_dict):
        calls.append((template, str(outpath)))
        return True

    # Avoid any side-effects inside setup_dicts by letting the real code run,
    # but nothing heavy happens in --generate branch.
    with patch.object(demo, "generate_file", side_effect=fake_generate_file):
        with pytest.raises(SystemExit) as ex:
            demo.main()
    assert ex.value.code == 0
    # Expect demo_backup_def.j2 and dar-backup.conf.j2 created under /tmp paths
    templates = [c[0] for c in calls]
    outs = [c[1] for c in calls]
    assert "demo_backup_def.j2" in templates
    assert "dar-backup.conf.j2" in templates
    assert any("/tmp/dar-backup-conf/backup.d/demo" in o for o in outs)
    assert any("/tmp/dar-backup-conf/dar-backup.conf" in o for o in outs)


def test_demo_generate_with_overrides(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "demo",
            "--generate",
            "--root-dir",
            "/tmp/root",
            "--dir-to-backup",
            "data",
            "--backup-dir",
            "/tmp/backups",
        ],
    )

    calls = []

    def fake_generate_file(args, template, outpath, vars_map, opts_dict):
        calls.append((template, vars_map.copy(), opts_dict.copy()))
        return True

    with patch.object(demo, "generate_file", side_effect=fake_generate_file):
        with pytest.raises(SystemExit) as ex:
            demo.main()

    assert ex.value.code == 0
    assert calls
    _, vars_map, opts_dict = calls[0]
    assert opts_dict["ROOT_DIR"] == "/tmp/root"
    assert opts_dict["DIR_TO_BACKUP"] == "data"
    assert opts_dict["BACKUP_DIR"] == "/tmp/backups"
    assert vars_map["ROOT_DIR"] == "/tmp/root"
    assert vars_map["DIR_TO_BACKUP"] == "data"
    assert vars_map["BACKUP_DIR"] == "/tmp/backups"


# Directory keys that main()'s --install branch itself creates. ROOT_DIR/
# DIR_TO_BACKUP are also present in a real vars_map, but the sample tree
# rooted there is populated by generate_sample_data(), which these
# orchestration tests patch out (see test_generate_sample_data_* below for
# coverage of that function's real filesystem/link behavior).
_INSTALL_DIR_KEYS = ("DAR_BACKUP_DIR", "BACKUP_DIR", "TEST_RESTORE_DIR", "CONFIG_DIR", "BACKUP_D_DIR")


# 3) --install happy path -> creates dirs and renders files into vars_map locations
def test_demo_install_ok(monkeypatch, tmp_path, capsys):
    # Prepare a clean vars_map so check_directories returns True
    vars_map = {
        "DAR_BACKUP_DIR": str(tmp_path / "dar-backup"),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
        "CONFIG_DIR": str(tmp_path / "etc"),
        "BACKUP_D_DIR": str(tmp_path / "backup.d"),
        "ROOT_DIR": str(tmp_path / "root"),
        "DIR_TO_BACKUP": "dir1",
    }
    opts_dict = {}

    # Patch argv -> triggers install branch
    monkeypatch.setattr(sys, "argv", ["demo", "--install"])

    # Patch setup_dicts to inject our temp dirs
    with patch.object(demo, "setup_dicts", return_value=(vars_map, opts_dict)):
        gen_calls = []

        def fake_generate_file(args, template, outpath, *_):
            gen_calls.append((template, str(outpath)))
            return True

        with patch.object(demo, "generate_file", side_effect=fake_generate_file):
            with patch.object(demo, "generate_sample_data", return_value=True) as fake_sample:
                with pytest.raises(SystemExit) as ex:
                    demo.main()

    assert ex.value.code == 0

    # Directories created
    for k in _INSTALL_DIR_KEYS:
        assert Path(vars_map[k]).exists()

    # Files rendered at expected locations
    assert any(
        t == "demo_backup_def.j2" and o == str(Path(vars_map["BACKUP_D_DIR"]) / "demo")
        for t, o in gen_calls
    )
    assert any(
        t == "dar-backup.conf.j2" and o == str(Path(vars_map["CONFIG_DIR"]) / "dar-backup.conf")
        for t, o in gen_calls
    )

    # Sample data generation was invoked for the default root/dir-to-backup
    fake_sample.assert_called_once()
    sample_root_arg = fake_sample.call_args.args[0]
    assert sample_root_arg == Path(vars_map["ROOT_DIR"]) / vars_map["DIR_TO_BACKUP"]

    out = capsys.readouterr().out
    assert "Directories created" in out


# 4) --install with existing dir and no --override -> error and exit 1
def test_demo_install_existing_no_override(monkeypatch, tmp_path, capsys):
    existing = tmp_path / "dar-backup"
    existing.mkdir(parents=True, exist_ok=True)

    vars_map = {
        "DAR_BACKUP_DIR": str(existing),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
        "CONFIG_DIR": str(tmp_path / "etc"),
        "BACKUP_D_DIR": str(tmp_path / "backup.d"),
        "ROOT_DIR": str(tmp_path / "root"),
        "DIR_TO_BACKUP": "dir1",
    }

    monkeypatch.setattr(sys, "argv", ["demo", "--install"])

    with patch.object(demo, "setup_dicts", return_value=(vars_map, {})):
        with pytest.raises(SystemExit) as ex:
            demo.main()

    assert ex.value.code == 1
    out = capsys.readouterr().out
    assert "already exist" in out or "overwrite" in out.lower()


# 5) --install with existing dirs but --override -> allowed
def test_demo_install_override_allows_existing(monkeypatch, tmp_path):
    # Precreate all dirs
    vars_map = {
        "DAR_BACKUP_DIR": str(tmp_path / "dar-backup"),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
        "CONFIG_DIR": str(tmp_path / "etc"),
        "BACKUP_D_DIR": str(tmp_path / "backup.d"),
        "ROOT_DIR": str(tmp_path / "root"),
        "DIR_TO_BACKUP": "dir1",
    }
    for k in _INSTALL_DIR_KEYS:
        Path(vars_map[k]).mkdir(parents=True, exist_ok=True)

    # Force parse_args to return a Namespace with override=True
    monkeypatch.setattr(sys, "argv", ["demo", "--install", "--override"])

    with patch.object(demo, "setup_dicts", return_value=(vars_map, {})):
        with patch.object(demo, "generate_file", return_value=True):
            with patch.object(demo, "generate_sample_data", return_value=True):
                with pytest.raises(SystemExit) as ex:
                    demo.main()

    assert ex.value.code == 0


# 6) Bad flag -> argparse exits with code 2
def test_demo_bad_flag(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["demo", "--nope"])
    with pytest.raises(SystemExit) as ex:
        demo.main()
    assert ex.value.code == 2


def test_demo_requires_grouped_options(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["demo", "--root-dir", "/tmp/root"])
    with pytest.raises(SystemExit) as ex:
        demo.main()
    assert ex.value.code == 2
    err = capsys.readouterr().err
    assert "must all be specified together" in err


def test_setup_dicts_updates_vars():
    vars_map = {
        "ROOT_DIR": "/default/root",
        "DIR_TO_BACKUP": "default",
        "BACKUP_DIR": "/default/backup",
    }
    args = _ns(root_dir="/custom/root", dir_to_backup="custom", backup_dir="/custom/backup")

    updated_vars, opts = demo.setup_dicts(args, vars_map)

    assert opts["ROOT_DIR"] == "/custom/root"
    assert opts["DIR_TO_BACKUP"] == "custom"
    assert opts["BACKUP_DIR"] == "/custom/backup"
    assert updated_vars["ROOT_DIR"] == "/custom/root"
    assert updated_vars["DIR_TO_BACKUP"] == "custom"
    assert updated_vars["BACKUP_DIR"] == "/custom/backup"


def test_generate_file_writes_and_respects_override(tmp_path):
    args = _ns(override=False)
    output_path = tmp_path / "demo"
    vars_map = {
        "ROOT_DIR": "/home/user",
        "DIR_TO_BACKUP": ".config/dar-backup",
        "DAR_BACKUP_DIR": "/tmp/dar-backup",
        "BACKUP_DIR": "/tmp/backups",
        "BACKUP_D_DIR": "/tmp/backup.d",
        "TEST_RESTORE_DIR": "/tmp/restore",
        "CONFIG_DIR": "/tmp/config",
    }

    result = demo.generate_file(args, "demo_backup_def.j2", output_path, vars_map, {})
    assert result is True
    original = output_path.read_text()
    assert "Demo of a `dar-backup` definition file" in original

    result = demo.generate_file(args, "demo_backup_def.j2", output_path, vars_map, {})
    assert result is False
    assert output_path.read_text() == original


def test_generate_file_rejects_directory_output(tmp_path, capsys):
    args = _ns(override=True)
    output_path = tmp_path / "outdir"
    output_path.mkdir()

    vars_map = {
        "ROOT_DIR": "/home/user",
        "DIR_TO_BACKUP": ".config/dar-backup",
        "DAR_BACKUP_DIR": "/tmp/dar-backup",
        "BACKUP_DIR": "/tmp/backups",
        "BACKUP_D_DIR": "/tmp/backup.d",
        "TEST_RESTORE_DIR": "/tmp/restore",
        "CONFIG_DIR": "/tmp/config",
    }

    result = demo.generate_file(args, "demo_backup_def.j2", output_path, vars_map, {})
    assert result is False
    out = capsys.readouterr().out
    assert "is a directory" in out


def test_generate_file_render_failure(tmp_path, monkeypatch, capsys):
    class FakeTemplate:
        def render(self, **_kwargs):
            return None

    class FakeEnv:
        def __init__(self, *args, **kwargs):
            pass

        def get_template(self, _template):
            return FakeTemplate()

    monkeypatch.setattr(demo, "Environment", FakeEnv)

    output_path = tmp_path / "out.conf"
    vars_map = {"ROOT_DIR": "/home/user", "DIR_TO_BACKUP": ".config/dar-backup"}

    result = demo.generate_file(_ns(override=True), "demo_backup_def.j2", output_path, vars_map, {})
    assert result is False
    assert not output_path.exists()

    out = capsys.readouterr().out
    assert "could not be rendered" in out


def test_check_directories_rejects_file(tmp_path, capsys):
    bad_path = tmp_path / "not-a-dir"
    bad_path.write_text("nope")

    vars_map = {
        "DAR_BACKUP_DIR": str(tmp_path / "dar-backup"),
        "BACKUP_DIR": str(bad_path),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
        "CONFIG_DIR": str(tmp_path / "etc"),
        "BACKUP_D_DIR": str(tmp_path / "backup.d"),
    }

    result = demo.check_directories(_ns(override=True), vars_map)
    assert result is False
    out = capsys.readouterr().out
    assert "not a directory" in out


# --- generate_sample_data() -------------------------------------------------

def test_generate_sample_data_creates_nested_tree_with_links(tmp_path):
    config_file = tmp_path / "dar-backup.conf"
    config_file.write_text("[MISC]\n")

    sample_root = tmp_path / "dir1"
    result = demo.generate_sample_data(sample_root, config_file, override=False)
    assert result is True

    # sample_root itself is the first of the 3 levels; _SAMPLE_SUBDIRS nests the other 2.
    levels = [sample_root]
    for name in demo._SAMPLE_SUBDIRS:
        levels.append(levels[-1] / name)
    assert len(levels) == len(demo._SAMPLE_ASSETS) == 3

    for current in levels:
        assert current.is_dir()

        jpeg_path = current / "color.jpg"
        assert jpeg_path.is_file()
        assert jpeg_path.read_bytes().startswith(b"\xff\xd8")  # JPEG magic bytes

        text_path = current / "color.txt"
        assert text_path.read_text().strip() == str(jpeg_path)

        symlink_path = current / "dar-backup.conf.symlink"
        assert symlink_path.is_symlink()
        assert symlink_path.resolve() == config_file.resolve()

        hardlink_path = current / "dar-backup.conf.hardlink"
        assert hardlink_path.is_file()
        assert not hardlink_path.is_symlink()
        assert hardlink_path.stat().st_ino == config_file.stat().st_ino

    # sample_root's direct children are exactly its own 4 files plus the next
    # nesting level's directory — no accidental extra "dir1" nested inside it.
    assert sorted(p.name for p in sample_root.iterdir()) == sorted(
        ["color.jpg", "color.txt", "dar-backup.conf.symlink", "dar-backup.conf.hardlink", demo._SAMPLE_SUBDIRS[0]]
    )


def test_generate_sample_data_rejects_existing_file(tmp_path, capsys):
    config_file = tmp_path / "dar-backup.conf"
    config_file.write_text("[MISC]\n")

    sample_root = tmp_path / "dir1"
    sample_root.write_text("not a directory")

    result = demo.generate_sample_data(sample_root, config_file, override=False)
    assert result is False
    out = capsys.readouterr().out
    assert "not a directory" in out
    # untouched
    assert sample_root.read_text() == "not a directory"


# --- cleanup() / _resolve_safe() -------------------------------------------

def test_cleanup_removes_the_three_managed_directories(monkeypatch, tmp_path):
    dar_backup_dir = tmp_path / "dar-backup"
    config_dir = tmp_path / "dar-backup-conf"
    data_dir = tmp_path / "dar-backup-data-dirs"
    for d in (dar_backup_dir, config_dir, data_dir):
        d.mkdir()
        (d / "marker").write_text("x")

    monkeypatch.setattr(demo, "DAR_BACKUP_DIR", str(dar_backup_dir))
    monkeypatch.setattr(demo, "CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(demo, "DATA_DIR", str(data_dir))

    result = demo.cleanup()
    assert result is True
    assert not dar_backup_dir.exists()
    assert not config_dir.exists()
    assert not data_dir.exists()


def test_cleanup_refuses_when_a_directory_is_a_symlink(monkeypatch, tmp_path):
    # A directory outside the demo's managed set, with data that must survive.
    real_other_dir = tmp_path / "somewhere-important"
    real_other_dir.mkdir()
    marker = real_other_dir / "do-not-delete"
    marker.write_text("precious")

    dar_backup_dir = tmp_path / "dar-backup"
    dar_backup_dir.symlink_to(real_other_dir)  # malicious/unintended redirection
    config_dir = tmp_path / "dar-backup-conf"
    config_dir.mkdir()
    data_dir = tmp_path / "dar-backup-data-dirs"
    data_dir.mkdir()

    monkeypatch.setattr(demo, "DAR_BACKUP_DIR", str(dar_backup_dir))
    monkeypatch.setattr(demo, "CONFIG_DIR", str(config_dir))
    monkeypatch.setattr(demo, "DATA_DIR", str(data_dir))

    result = demo.cleanup()
    assert result is False

    # Nothing was removed: the symlink is untouched, and critically, the
    # real directory it points at (and its content) must survive.
    assert dar_backup_dir.is_symlink()
    assert real_other_dir.exists()
    assert marker.read_text() == "precious"
    # The other two, unaffected directories were also left alone (all-or-nothing).
    assert config_dir.exists()
    assert data_dir.exists()


# --- CLI: --cleanup ----------------------------------------------------------

def test_demo_cleanup_flag_success(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["demo", "--cleanup"])
    with patch.object(demo, "cleanup", return_value=True):
        with pytest.raises(SystemExit) as ex:
            demo.main()
    assert ex.value.code == 0


def test_demo_cleanup_flag_failure_exits_1(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["demo", "--cleanup"])
    with patch.object(demo, "cleanup", return_value=False):
        with pytest.raises(SystemExit) as ex:
            demo.main()
    assert ex.value.code == 1
