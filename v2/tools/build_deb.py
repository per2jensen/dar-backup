#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
#
# build_deb.py — Build and sign a .deb package for dar-backup
#
# This script is intended to be placed at: v2/tools/build_deb.py
#
# Usage:
#     python3 tools/build_deb.py <version-tag>
#
# It performs the following:
#   - Verifies the provided tag matches the version in pyproject.toml
#   - Builds the dar-backup wheel using Hatch
#   - Installs the wheel into a temporary directory
#   - Constructs a Debian package layout under:
#       v2/packages/deb/dar-backup_<version>
#   - Adds executable wrapper scripts to /usr/bin
#   - Generates a Debian control file from a template
#   - Builds a .deb file using dpkg-deb
#   - Signs the .deb using your GPG key (defined in project metadata)
#
# Expected:
#   - Python source is structured using PEP 621 and the src/ layout
#   - GPG key is already set up and unlocked for signing
#
# Maintainer: Per Jensen <dar-backup@pm.me>

import sys
import subprocess
import tempfile
import shutil
import os
import re
from pathlib import Path
import tomllib

def run(cmd, **kwargs):
    cmd_strs = list(map(str, cmd))
    print(f"$ {' '.join(cmd_strs)}")
    subprocess.run(cmd_strs, check=True, **kwargs)


def load_version_from_pyproject(pyproject_path):
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)

    # If version is dynamic, load it from __about__.py
    if "version" not in data.get("project", {}):
        hatch_cfg = data.get("tool", {}).get("hatch", {}).get("version", {})
        path = hatch_cfg.get("path")
        if not path:
            raise ValueError("❌ 'version' is dynamic but no path defined under [tool.hatch.version]")
        about_file = pyproject_path.parent / path
        about_data = about_file.read_text()
        match = re.search(r'__version__\s*=\s*[\'"]([^\'"]+)[\'"]', about_data)
        if not match:
            raise ValueError("❌ Could not find __version__ in about file")
        return match.group(1)

    return data["project"]["version"]

def build_deb(tag):
    v2_dir = Path(__file__).resolve().parent.parent
    pyproject = v2_dir / "pyproject.toml"
    version = load_version_from_pyproject(pyproject)

    if tag != version:
        print(f"❌ Tag {tag} does not match version {version} in pyproject.toml")
        sys.exit(1)

    run(["hatch", "build"])

    dist_dir = v2_dir / "dist"
    deb_root = v2_dir / "packages" / "deb" / f"dar-backup_{version}"
    if deb_root.exists():
        shutil.rmtree(deb_root)
    site_packages = deb_root / "usr" / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    os.makedirs(site_packages, exist_ok=True)

    with tempfile.TemporaryDirectory() as tempdir:
        run([
            sys.executable, "-m", "pip", "install",
            str(next(dist_dir.glob("*.whl"))),
            "--no-deps", "--target", tempdir,
        ])
        shutil.copytree(tempdir, site_packages, dirs_exist_ok=True)

    print("📦 Vendoring 'inputimeout' from PyPI into .deb")
    run([
        sys.executable, "-m", "pip", "install",
        "inputimeout", "--target", str(site_packages)
    ])
    site_packages.chmod(0o755)

    # Remove .pth file if exists
    for pth in site_packages.glob("*.pth"):
        print(f"⚠️ Removing leftover .pth file: {pth}")
        pth.unlink()

    # Add control file
    debian_dir = deb_root / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)
    template_path = v2_dir / "packages" / "deb" / "templates" / "control.template-default"
    control_path = debian_dir / "control"
    with open(template_path) as f:
        control_contents = f.read().replace("{version}", version)
    control_path.write_text(control_contents)

    # Add executables
    bin_dir = deb_root / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli_names = {
        "dar-backup": "dar_backup",
        "dar-backup-clean-log": "clean_log",
        "dar-backup-cleanup": "cleanup",
        "dar-backup-demo": "demo",
        "dar-backup-installer": "installer",
        "dar-backup-manager": "manager",
        "dar-backup-systemd": "dar_backup_systemd"
    }

    for cli, module in cli_names.items():
        bin_path = bin_dir / cli
        bin_path.write_text(
           f"""#!/bin/sh
PYTHONPATH="$(dirname $(dirname $(readlink -f "$0")))/lib/$(python3 -c 'import sys; print(f"python{{sys.version_info.major}}.{{sys.version_info.minor}}")')/site-packages"
export PYTHONPATH
exec python3 -m dar_backup.{module} "$@"
"""
        )
        bin_path.chmod(0o755)

    output_deb = v2_dir / "packages" / "deb" / f"dar-backup_{version}_all.deb"
    run(["fakeroot", "dpkg-deb", "--build", deb_root, output_deb.parent])
    run([
        "gpg", "--armor", "--detach-sign", "--local-user",
        "B54F5682F28DBA3622D78E0458DBFADBBBAC1BB1", str(output_deb)
    ])

    print(f"✅ .deb created and signed: {output_deb}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 build_deb.py <version-tag>")
        sys.exit(1)
    build_deb(sys.argv[1])

