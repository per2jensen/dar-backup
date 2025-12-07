# SPDX-License-Identifier: MIT

"""
Source code is here: https://github.com/per2jensen/clonepulse

MIT License

Copyright (c) 2025 Per Jensen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

import clonepulse.__about__ as about
import os
import re
import sys

from pathlib import Path

def get_invocation_command_line() -> str:
    """
    Safely retrieves the exact command line used to invoke the current Python process.

    On Unix-like systems, this reads from /proc/[pid]/cmdline to reconstruct the
    command with interpreter and arguments. If any error occurs (e.g., file not found,
    permission denied, non-Unix platform), it returns a descriptive error message.

    Returns:
        str: The full command line string, or an error description if it cannot be retrieved.
    """
    try:
        cmdline_path = f"/proc/{os.getpid()}/cmdline"
        with open(cmdline_path, "rb") as f:
            content = f.read()
            if not content:
                return "[error: /proc/cmdline is empty]"
            return content.replace(b'\x00', b' ').decode().strip()
    except Exception as e:
        return f"[error: could not read /proc/[pid]/cmdline: {e}]"


def show_scriptname()  -> str:
    """
    Return script name, useful in start banner for example
    """
    try:
        scriptname = os.path.basename(sys.argv[0])
    except:
        scriptname = "unknown"
    return scriptname


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {about.__version__}")
    print(f"{script_name} source code is here: https://github.com/per2jensen/clonepulse")
    print(about.__license__)



def extract_version(output):
    match = re.search(r'(\d+\.\d+(\.\d+)?)', output)
    return match.group(1) if match else "unknown"


def expand_path(path: str) -> str:
    """
    Expand ~ and environment variables like $HOME in a path.
    """
    return os.path.expanduser(os.path.expandvars(path))


def normalize_dir(path: str) -> str:
    """
    Strip any trailing slash/backslash but leave root (“/” or “C:\\”) intact.
    """
    p = Path(path)
    # Path(__str__) drops any trailing separators
    normalized = str(p)
    return normalized


