#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
build_deb.py — Build and sign a .deb package for dar-backup

This script is intended to be placed at: v2/tools/build_deb.py

Usage:
    python3 tools/build_deb.py <version-tag>

It performs the following:
  - Verifies the provided tag matches the version in pyproject.toml
  - Builds the dar-backup wheel using Hatch
  - Installs the wheel into a temporary directory
  - Constructs a Debian package layout under:
      v2/packages/deb/dar-backup_<version>
  - Adds executable wrapper scripts to /usr/bin
  - Generates a Debian control file
  - Builds a .deb file using dpkg-deb
  - Signs the .deb using your GPG key (defined in project metadata)

Expected:
  - Python source is structured using PEP 621 and the src/ layout
  - GPG key is already set up and unlocked for signing

Maintainer: Per Jensen <dar-backup@pm.me>
"""


import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
import tomllib

def run(cmd, **kwargs):
    cmd_strs = list(map(str, cmd))  # Convert Path objects to str
    print(f"$ {' '.join(cmd_strs)}")
    subprocess.run(cmd_strs, check=True, **kwargs)

def load_version_from_pyproject(pyproject_path):
    with open(pyproject_path, "rb") as f:
        config = tomllib.load(f)
    version_file = config["tool"]["hatch"]["version"]["path"]
    version_path = pyproject_path.parent / version_file
    about = {}
    with open(version_path, "r") as f:
        exec(f.read(), about)
    return about["__version__"]

def build_deb(tag):
    v2_dir = Path(__file__).resolve().parent.parent
    pyproject = v2_dir / "pyproject.toml"
    version = load_version_from_pyproject(pyproject)

    if version != tag:
        print(f"❌ Version mismatch: pyproject.toml says {version}, but you passed tag {tag}")
        sys.exit(1)

    # Step 1: Build wheel
    dist_dir = v2_dir / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    run(["hatch", "build"], cwd=v2_dir)

    # Step 2: Install wheel into staging area
    deb_root = v2_dir / "packages" / "deb" / f"dar-backup_{version}"
    if deb_root.exists():
        shutil.rmtree(deb_root)

    with tempfile.TemporaryDirectory() as tempdir:
        run([
            sys.executable, "-m", "pip", "install",
            str(next(dist_dir.glob("*.whl"))),
            "--no-deps", "--target", tempdir,
        ])
        site_packages = deb_root / "usr" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
        site_packages.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(tempdir, site_packages, dirs_exist_ok=True)

        # Remove unwanted bin/ from site-packages
        bin_inside = site_packages / "bin"
        if bin_inside.exists():
            shutil.rmtree(bin_inside)
        # Remove all .pyc files
        for pyc in site_packages.rglob("*.pyc"):
            pyc.unlink()


    # Step 3: Create CLI wrappers in /usr/bin
    bin_dir = deb_root / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli_names = {
        "dar-backup": "main",
        "dar-backup-cleanup": "cleanup",
        "dar-backup-clean-log": "clean_log",
        "dar-backup-manager": "manager",
        "dar-backup-demo": "demo",
        "dar-backup-installer": "installer",
        "dar-backup-systemd": "dar_backup_systemd"
    }
    for cli, module in cli_names.items():
        bin_path = bin_dir / cli
        bin_path.write_text(f"#!/bin/sh\npython3 -m dar_backup.{module} \"$@\"\n")
        bin_path.chmod(0o755)

    # Step 4: Create DEBIAN/control from template
    debian_dir = deb_root / "DEBIAN"
    debian_dir.mkdir()
    template_dir = v2_dir / "packages" / "deb" / "templates"
    template_path = template_dir / f"control.template-{version}"
    if not template_path.exists():
        template_path = template_dir / "control.template-default"
    template = template_path.read_text()
    (debian_dir / "control").write_text(template.format(version=version))

    # Step 5: Build .deb
    output_deb = deb_root.parent / f"dar-backup_{version}_all.deb"
    if output_deb.exists():
        output_deb.unlink()
    run(["dpkg-deb", "--build", deb_root, output_deb.parent])

    # Step 6: Sign .deb with GPG
    os.environ["GPG_TTY"] = os.popen("tty").read().strip()
    run(["gpg", "--armor", "--detach-sign", "--local-user", "B54F5682F28DBA3622D78E0458DBFADBBBAC1BB1", str(output_deb)])

    print(f"✅ .deb created and signed: {output_deb}")

    # Clean up staging tree
    shutil.rmtree(deb_root)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: tools/build_deb.py <version-tag>")
        sys.exit(1)
    build_deb(sys.argv[1])