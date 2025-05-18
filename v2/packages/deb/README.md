
# Notes

## inputimeout not available on Debian 12  and Ubuntu 25.04

💡 Note:
This package bundles `inputimeout` from PyPI because it is not yet available in Debian/Ubuntu repositories.
All other dependencies are installed using your system package manager.

# Note

 'inputimeout' is NOT listed in Depends because it is not available in Debian/Ubuntu APT repositories.
 It is vendored directly from PyPI during build in tools/build_deb.py.
 If it becomes available in APT in the future, you may consider replacing the vendored version.