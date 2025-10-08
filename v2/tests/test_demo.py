# tests/test_demo.py
import sys
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch, MagicMock
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
