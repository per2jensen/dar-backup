#!/usr/bin/env python3
import sys
import os

def main():
    if len(sys.argv) != 2:
        print("Usage: verify-signature.sh <package.whl> | <package.tar.gz>")
        sys.exit(1)

    file = sys.argv[1]
    asc_file = file + ".asc"

    if not os.path.exists(file):
        print(f"Error: file {file} not found")
        sys.exit(1)

    if not os.path.exists(asc_file):
        print(f"Error: signature file {asc_file} not found")
        sys.exit(1)

    print(f"Verifying: {file} with {asc_file}...")
    os.system(f"gpg --verify {asc_file} {file}")


