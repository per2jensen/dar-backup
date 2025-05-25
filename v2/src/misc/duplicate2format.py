#!/usr/bin/env python3
# SPDF License: GPL-3.0 or later

"""
Let `black` format a copy of --src <directory>

No changes to the original source directory.


💡 Key features

Options (--src, --dest)
  --src <directory>  Source directory to copy and format (default: src)
  --dest <directory> Destination directory for the formatted copy (default: src-formatted)
Graceful error handling (checks if source exists)
Uses shutil.copytree for fast recursive copying
Runs `black` on the destination directory
"""


import argparse
import shutil
import subprocess
import os
import sys

def main():
    parser = argparse.ArgumentParser(
        description="Copy a source directory to a destination and run black on the destination."
    )
    parser.add_argument(
        "--src",
        default="src",
        help="Source directory to copy and format (default: src).",
    )
    parser.add_argument(
        "--dest",
        default="src-formatted",
        help="Destination directory for the formatted copy (default: src-formatted).",
    )

    args = parser.parse_args()
    src_dir = args.src
    dest_dir = args.dest

    # If --dest exists, exit
    if os.path.exists(dest_dir):
        print(
            f"❌ Destination '{dest_dir}' already exists. "
            "Provide a custom --dest directory to proceed."
        )
        exit(1)

    if not os.path.exists(src_dir):
        print(f"❌ Source directory '{src_dir}' does not exist.")
        exit(1)

    print(f"🔧 Copying '{src_dir}' to '{dest_dir}'...")
    shutil.copytree(src_dir, dest_dir, dirs_exist_ok=True)
    print("✅ Copy complete.")

    # Find black inside the active virtual environment
    venv_bin_dir = os.path.dirname(sys.executable)
    black_path = os.path.join(venv_bin_dir, "black")

    print(f"🎨 Running black on '{dest_dir}'...")
    subprocess.run([black_path, dest_dir], check=True)
    print(f"✅ Formatting complete. Formatted code in: {dest_dir}")


if __name__ == "__main__":
    main()
