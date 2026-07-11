# After a release, seed the next dev cycle as "X.Y.Z.dev0" (numeric suffix
# required). scripts/pre-commit-version-bump.sh only increments an existing
# ".devN" counter on each commit — it won't create one from a bare "X.Y.Z" or
# a malformed suffix like "X.Y.Z-dev"/"X.Y.Z.dev", so those are silently
# skipped and the version never advances until re-seeded with ".dev0".
__version__ = "1.1.11.dev16"

__author__ = "Per Jensen"

__license__ = '''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.'''
