# Catalogs

## Introduction
A dar_manager catalog keeps track of which files are in which archives, and helps restoring the correct version of any given file.

dar_manager docs are here:

- [dar_manager man page](http://dar.linux.free.fr/doc/man/dar_manager.html)
- [dar tutorial](http://dar.linux.free.fr/doc/Tutorial.html)

## Issues

### My cloud drive

Adding dar archives to a catalog for my cloud disk backups often gives this error:

```
Dates of file's data are not increasing when database's archive number grows. Concerned file is: <the file>
```

I do not see this error on any of the catalogs with backups of local file systems.

Currently the script logs a warning and keeps going. It needs some more investigation.

