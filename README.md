
# Full, differential or incremental backups using `dar`

The wonderful `dar` [Disk Archiver](https://github.com/Edrusb/DAR) is used for
the heavy lifting, together with the [The Parchive suite](https://github.com/Parchive) in these scripts.

## License

These scripts are licensed under the GPLv3 license.
Read more here: [GNU GPL 3.0](https://www.gnu.org/licenses/gpl-3.0.en.html),
or have a look at the ["LICENSE"](https://github.com/per2jensen/dar-backup/blob/main/LICENSE)
file in this repository.

## Github locations

'dar-backup' lives at [Github](https://github.com/per2jensen/dar-backup)

- [**'dar-backup' v2**](https://github.com/per2jensen/dar-backup/tree/main/v2)
  - [v2 is Python based, install from PyPI](https://pypi.org/project/dar-backup/)

- ['dar-backup' v1](https://github.com/per2jensen/dar-backup/tree/main/v1)

## My use case

 I have cloud storage mounted on a directory within my home dir. The filesystem is
 [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which
 gives it a few special features:

- a non-privileged user (me :-)) can perform a mount
- a privileged user cannot look into the filesystem --> a backup script running as root is not suitable

I needed the following:

- General purpose backup system, which has saved my bacon on some occasions.
- Backup my cloud storage to something local (cloud is convenient, but I want control over my backups).
- Backup primarily photos, video and different types of documents.
- Have a simple way of restoring, possibly years into the future.
  - 'dar' fits that scenario with a single statically linked binary (kept with the archives).
  - There is no need install/configure anything - restoring is simple and works well.
- During backup archives must be tested and a restore test (however small) performed.
- Utilize Parchive to create redundancy to increase the chance of fixing bitrot in the archives down the line.
- Verify archive's integrity, after it has been moved around, or copied somewhere.

 I do not need the encryption features of dar, as all storage is already encrypted.

## Projects these scripts benefit from

 1. [The wonderful dar achiver](https://github.com/Edrusb/DAR)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [shellcheck - a bash linter](https://github.com/koalaman/shellcheck)
 4. [Ubuntu of course :-)](https://ubuntu.com/)
 5. [PyPI](https://pypi.org/)
