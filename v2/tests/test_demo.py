# tests/test_demo.py
import sys
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch
import pytest

import dar_backup.demo as demo


def _ns(**kw):
    # Defaults that demo.main() may reference
    base = dict(
        install=False,
        generate=False,
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
    assert any("/tmp/dar-backup/backup.d/demo" in o for o in outs)
    assert any("/tmp/dar-backup.conf" in o for o in outs)


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


# 3) --install happy path -> creates dirs and renders files into vars_map locations
def test_demo_install_ok(monkeypatch, tmp_path, capsys):
    # Prepare a clean vars_map so check_directories returns True
    vars_map = {
        "DAR_BACKUP_DIR": str(tmp_path / "dar-backup"),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "TEST_RESTORE_DIR": str(tmp_path / "restore"),
        "CONFIG_DIR": str(tmp_path / "etc"),
        "BACKUP_D_DIR": str(tmp_path / "backup.d"),
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
            with pytest.raises(SystemExit) as ex:
                demo.main()

    assert ex.value.code == 0

    # Directories created
    for k in vars_map:
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
    }
    for v in vars_map.values():
        Path(v).mkdir(parents=True, exist_ok=True)

    # Force parse_args to return a Namespace with override=True
    monkeypatch.setattr(sys, "argv", ["demo", "--install", "--override"])

    with patch.object(demo, "setup_dicts", return_value=(vars_map, {})):
        with patch.object(demo, "generate_file", return_value=True):
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
