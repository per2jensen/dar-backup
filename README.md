
# Full, differential or incremental backups using 'dar' 

  The wonderful 'dar' (Disk Archiver) (https://github.com/Edrusb/DAR) is used for 
  the heavy lifting, together with the par2 suite in these scripts.

# Github location
This 'dar-backup' package lives at: https://github.com/per2jensen/dar-backup

# My use case
 I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features
 - a non-privileged user (me :-)) can perform a mount
 - a privileged user cannot look into the filesystem --> a backup script running as root is not suitable

 I needed the following:
 - Backup my cloud storage to something local (cloud is convenient, but I want control over my backups)
 - Backup primarily photos, video and different types of documents
 - Have a simple non-complicated way of restoring, possibly years into the future. 'dar' fits that scenario with a single statically linked binary (kept with the archives). There is no need install/configure anything - restoring is simple and works well.
 - During backup archives must be tested and a restore test (however small) performed
 - Archives stored on a server with a reliable file system (easy to mount a directory over sshfs)
 - Easy to verify healthy archives, when they are moved around.

 I do not need the encryption features of dar, as all storage is already encrypted.
 

# Inspiration

  I have used 'dar' before, and is now back. Thank you Denis Corbin for a great
  backup solution and for 20+ years of work/support. Outstanding!

  The dar mini-howto has been inspirational, it is a very good read, kudos to 
  Grzegorz Adam Hankiewicz
  https://dar.sourceforge.io/doc/mini-howto/dar-differential-backup-mini-howto.en.html


  These are some of the features and workflows, that are plusses in my book:
  
  - 'dar' itself is rock solid and has been for years, it truly is a great tool. Don't think this is another 'tar', it is way better.

  - I like being able to verify that an archive is good, once it has been stored remotely. When I copy the archives from the server to somewhere else, I am again able to verify that the archive is healthy.

  - The built in par2 integration provides a method to maybe be able to salvage a broken archive in the future.

# How to install
  - Download a dar-backup tar file from the (releases)[https://github.com/per2jensen/dar-backup/releases] 
  - untar 
    ````
    tar zxf <the-tar-file> --directory <a-directory-under-which-darbackup-is-untarred>
    ````
  - make install script executable
    ````
    chmod +x <a-directory-under-which-darbackup-is-untarred>/dar-backup/bin/install.sh
    ````
  - Run install.sh
    ````
    <a-directory-under-which-darbackup-is-untarred>/dar-backup/bin/install.sh
    ````

  - Take a backup of the installation
    ````
    <a-directory-under-which-darbackup-is-untarred>/dar-backup/bin/dar-backup.sh --local-backup-dir
    ````

  - View the log file
    ````
    cat <a-directory-under-which-darbackup-is-untarred>/dar-backup/archives/dar-backup.log
    ````
    During installation, a directory has been created "<a-directory-under-which-darbackup-is-untarred>/dar-backup/archives", where the backups have been stored.


  The programs stay where untarred, when running the installer.
  
  It makes scripts executable, creates some soft links, sets up references to the various config files used and lastly generates systemd service files.

# Script features

  - Take full backups, differential backups or incremental backups
  - Uses the par2 functionality for file repair, 5% error correction configured
    - 3 8K blocks bitrot in a test archive is repairable (see [testcase1](https://github.com/per2jensen/dar-backup/blob/main/test/test-parchive.sh), [testcase2](https://github.com/per2jensen/dar-backup/blob/main/test/test-parchive-multiple-8k-blocks.sh)) 
  - http://dar.linux.free.fr/doc/usage_notes.html#Parchive 
  - Test the archive after a backup
  - Search for a file < 10MB, and restore it under /tmp as part of the backup
  - Copies dar_static to server (handy to have the statically linked binary available in the future)
  - Simple to add backups, including directories to include and to exclude in each backup
  - Run a single backup definition from backups.d/
  - Systemd services and schedules for FULL, DIFF & INC ready to be dropped into ~/.config/systemd/user (see share/)
  - sshfs *can* be used to mount remote directory (this was previously hard coded into the script)
    - sshfs uses [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), allowing a non-privileged user to mount remote storage.
  - Logs to a logfile in a user configured directory
  - Can save all output to a debug log file, handy if dar exit code is 5 (number files not backed up are listed)
  - Status messages are sent to a Discord hook, change the sendDiscordMsg() function to suit your needs
  - test cases: an automatic backup test is now performed on every commit using Githup actions

# Invocation

 - FULL backup of files/directories in the backup definition

 ````
 dar-backup.sh
 ````

 - DIFF backup of files/directories in the backup definition

 The diff is made against the newest full backup of the definition

 ````
 dar-diff-backup.sh
 ````

 - INCREMENTAL backup of files/directories in the backup definition

 The incremental is made against the newest diff backup of the definition, *regardless if there is a newer FULL*

 ````
 dar-inc-backup.sh
 ````



# Requirements
  - sshfs (if mounting a server directory)
  - dar
  - par2
  - curl

  On Ubuntu, install the requirements this way:
  ````
    sudo apt install sshfs dar dar-static par2 curl
  ````

# Options

  The script has a few options to modify it's behavior:

##  --backupdef definition

  Run only a single backup definition, instead of all definitions kept in the backups.d directory

  'definition' is one of the filenames in backups.d/

## --list-files

  Use this option to see what will be backed up.
  The result is stored in one of /tmp/dar-{FULL|DIFF|INC}-filelist.txt, depending on what type of backup you choose.

## --local-backup-dir

  Make the script bypass mounting a remote server directory using sshfs. The backup archives are stored in the "MOUNT_POINT" config setting. This directory can of course be mounted by some other method :-)

## --debug
  Make bash print all statements via the "set -x" option. Save output to debug log file.


## --help

  Terse usage information

# How to use
  
  I use Ubuntu on my workstation, so this script is a 'bash' script. The 'dar' program is from the Ubuntu package, I also have par2 installed.

  Although I use the sshfs mount method, you don't need to. Use the "--local-backup-dir" option to bypass the server mount.
  Also I have set up a Discord account that receives messages, it is easy to change that in the sendDiscordMsg() function.

  The recipe for me to get this script running is the following:   

  - Setup an ssh access using a key for logging into the server
  - A Discord webhook is needed for the messages to be sent
  - A 'darrc' file is generated in the conf dir, once the install.sh script has been run.
    It controls which files not to compress, and points to the par2 configuration, also in
    conf dir
  - Fill in some data in the dar-backup.conf file, and delete the 2 lines at the top
    ````
     Environment variables.

      # the Discord webhook address to send messages to
      DISCORD_WEBHOOK="the long Discord webhook here"

      # server name or ip address
      # not relevant if --local-backup-dir is used
      SERVER=some-server 

      # the directory on the server used to store backups
      # not relevant if --local-backup-dir is used
      SERVER_DIR=/some/dir

      # dar archives are written here
      # use --local-backup-dir for not trying to do an sshfs mount
      # TODO rename to something like ARCHIVE_DIR
      MOUNT_POINT=/tmp/dar-backup-archives

      # path to log file
      LOG_LOCATION=/tmp/dar-backup-test/

      # should all output be captured in a file
      DEBUG=n

      # path to debug log file
      DEBUG_LOCATION=/tmp/dar-debug.log
    ````
  - Define backups in the "backups.d" directory, just drop files in the directory
  
    Alter the demo backups.d/dar-backup file to your taste
  
    ````
    # Set backup root
    -R /home/pj/tmp

    # Directories to backup below the root dir set above, add as many directories as you want on new lines
    -g dba 

    # Directories to exclude, add as many directories as you want on new lines
    -P "dba/first dir"
    ````

  - Make the install.sh script executable and run it. 
  
  The install.sh script installs (among a few other things) the backup definitions from the templates/backups.d directory. If you keep your backup definitions in the templates/backups.d directory and install them via the install.sh script, it is easy to change the location of the dar-backup solution at a later point. 
    ````
    chmod +x install.sh
    ./install.sh
    ````
  
  - Execute the script and "list" the dar archive to check that the backup is to your liking
    ````
    # do the backup
    .\dar-backup.sh
    
    # list the archive
    dar -l /PATH/TO/ARCHIVE |less
    ````

    **observe:** the archive name dar expects is without the "<slice number>.dar", so if you have the following dar archive in 3 slices:

    |File name|
    ---|
    |TEST_FULL_2021_08_29.1.dar|
    |TEST_FULL_2021_08_29.2.dar|
    |TEST_FULL_2021_08_29.3.dar|

    the archive name is: 'TEST_FULL_2021_08_29'

# darrc
  The scripts do not use ~/.darrc nor do they use /etc/darrc

  The defaults used by the scripts (for example file types not to compress) are linked by backup definitions. The defaults are stored in conf/defaults-rc.

  The demo backup definition templates/backups.d/dar-backup links defaults-rc in the first directive.

# Examples

## how to run a single backup definition
  Backup definitions are placed in the backups.d/ directory. Each definition corresponds to a separate 'dar' archive.
  By default the dar-backup.sh loops over all definitions and runs the specified backups.

  If you want to just run a single backup definition, do it like this:
  ````
  dar-backup.sh -d "the definition"
  ````
  where "the definition" is the filename in backups.d/
  
## how to test that the archive is healthy
  If you have copied the archive somewhere, it gives peace of mind to know the archive is still healthy.
  ````
  dar -vd -t <the archive>
  ````
  Remember that the archive name is without "slice_number.dar"

  Another way to verify the archives is to use [par2 verification](#par2-verification)

## how to restore a directory
  I do a "list" and "grep" like this
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  Remember that the archive name is without "slice_number.dar"
  Once I have located the directory to restore, do like this (here the restore is below /tmp)
  ````
  dar  -x ~/path/to/archive -R /tmp -g <the directory you want to restore>
  ````
  
  **Example:**
  
  I did a FULL backup of various data January 8, 2022. I also on that date took some photos of my new Seiko wrist watch, and played with flash light. Here I test the restore of the Seiko photos from my media-files backup.

  dar archive name: media-files_FULL_2022-01-08 (located in /home/pj/mnt/dar, a remote directory mounted here) 
  
  Location of restore:  /data/tmp

  Name of directory to restore: home/pj/data/2022/2022-01-08-Seiko  (this is the location with respect to the full backup "-R" setting = "/")

  ````
  dar -x /home/pj/mnt/dar/media-files_FULL_2022-01-08 -R /data/tmp -g home/pj/data/2022/2022-01-08-Seiko

 --------------------------------------------
 32 inode(s) restored
    including 0 hard link(s)
 0 inode(s) not restored (not saved in archive)
 0 inode(s) not restored (overwriting policy decision)
 6 inode(s) ignored (excluded by filters)
 0 inode(s) failed to restore (filesystem error)
 0 inode(s) deleted
 --------------------------------------------
 Total number of inode(s) considered: 38
 --------------------------------------------
 EA restored for 0 inode(s)
 FSA restored for 0 inode(s)
 --------------------------------------------
  ````
 I can now check out the directory */data/tmp/home/pj/data/2022/2022-01-08-Seiko*, and verify the restore worked (it did).



## how to restore a single file
  Much like restoring a directory, I seek out the file with a "list" and "grep"
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  and the tell dar to go into (-g) a specific directory and restore the specific file
  ````
  dar -x /path/to/archive -R /tmp -g path/to/directory/in/archive/file_to_restore
  ````
  
  The "-I" option works on the file name only, and not path/file-name as the "-g" option. So using "-I" could select and restore more than one file in a directory tree.
  

## <a id="par2-verification"></a>  par2 verification/repair
You can run a par2 verification on an archive like this:
````
for file in <archive>*.dar.par2; do
  par2 verify "$file"
done
````
if there are problems with a slice, try to repair it like this:
````
  par2 repair <archive>.<slice number>.dar.par2
````

## <a id="par2-redundency"></a> par2 create redundency files
If you have merged archives, you will need to create the .par2 redundency files manually.
Here is an example
````  
for file in <some-archive>_FULL_yyyy-mm-dd.*; do
  par2 c -r5 -n1 "$file"
done
````  
where "c" is create, -r5 is 5% redundency and -n1 is 1 redundency file
  
## performance tip
  This [dar benchmark page](https://dar.sourceforge.io/doc/benchmark.html) has an interesting note on the slice size.
  
  Slice size should be smaller than available RAM, apparently a large performance hit can be avoided keeping the the par2 data in memory.
  
## overview of archives
Once you har a fair amount of archives, it can become a bit hard to have an overview of what's there.
One way to get an overview is to use the script 'ls-archives.sh'

Here is a (fictive files) example:
````
 ~ programmer/dar-backup/bin/ls-archives.sh
Mountpoint: /home/pj/mnt/dar
pj_homedir_DIFF_2022-03-27     slices: 1   (4G) total: 3,7G   Saved: 1216    Removed: 227     
pj_homedir_FULL_2022-01-08     slices: 5   (7G) total: 36G    Saved: 82301   Removed: 0       
pj_homedir_INC_2022-04-03      slices: 1   (1G) total: 654M   Saved: 130     Removed: 6       
pj_homedir_INC_2022-04-09      slices: 1   (1G) total: 714M   Saved: 474     Removed: 11      
pj_homedir_INC_2022-04-12      slices: 1   (4G) total: 3,3G   Saved: 858     Removed: 19
Total disk usage in /home/pj/mnt/dar: 47G 

````
"Saved" is the number of files saved in the archive.

"Removed" is the number of files (and directories I think), that was not found during the backupm but is present in the archive file list.

If you see an archive that is significantly smaller than a previous one (for example fewer slices), or a ton of files have been removed, you should probably find out why that is. There may be good reasons like:
 
  - You have cleaned up
  - The backup definition has more excludes

It could also be an error, so it is good to know why archive sizes change over time.

For convenience it also prints that total amount of storage used in the directory used.

The reason the total is bigger than the sum of slices, is that the total includes parity files.

## merge FULL with DIFF, creating new FULL
  Over time, the DIFF archives become larger and larger. At some point one wishes to create a new FULL archive to do DIFF's on.
  One way to do that, is to let dar create a FULL archive from scratch, another is to merge a FULL archive with a DIFF, and from there do DIFF's until they once again gets too large for your taste.
  
  I do backups of my homedir. Here it is shown how a FULL archive is merged with a DIFF, creating a new FULL archive.
  ````
  dar --merge pj_homedir_FULL_2021-09-12  -A pj_homedir_FULL_2021-06-06  -@pj_homedir_DIFF_2021-08-29 -s 12G
  
  # test the new FULL archive
  dar -t pj_homedir_FULL_2021-09-12
  ````
  *Remember* to create new par2 redundency files, see the [redundency section](#par2-redundency).


  **Notes**
  
  1. When not providing an --overwriting-policy, the dar default is "Oo", which means use the file from the "adding" archive (-@ option), and also the extended atttibutes from that file also. To me, that is the natural way of merging the two archives.
  2. I specified "-ak" to prevent decompressing/compressing - that didn't work, due to different compression types used in the 2 archives (it is a feature for a future version of dar though)

## verbosity
The file conf/defaults-rc contains various verbosity settings, that can be enabled by removing the "#" char. A brief explanation to each option is provided.

## trim the log file 
  'dar' notes every directory is has processed, that can clutter the log file. If you want to trim the log file after the fact, try this:
  ````
  # remove lots of directory notices from the log file
  sed -i '/^Inspecting directory/d' ~/dar-backup.log
  
  # remove more directory notices from the log file
  sed -i '/^Finished Inspecting/d' ~/dar-backup.log 
  ````   

## list all dar archives, sorted on slice number
If you want to check that all slices are found for an archive, you can use the commands shown below.

In this example, I am listing my archive "media-files_FULL_" for the date set in the DARDATE env variable.

````
DARDATE=2022-01-08
# slices with 1 number
ls media-files_FULL_${DARDATE}.*.dar|egrep media-files_FULL_${DARDATE}[.][0-9][.] -o |sort -u
# slices with 2 numbers
ls media-files_FULL_${DARDATE}.*.dar|egrep media-files_FULL_${DARDATE}[.][0-9][0-9][.] -o |sort -u
# slices with 3 numbers
ls media-files_FULL_${DARDATE}.*.dar|egrep media-files_FULL_${DARDATE}[.][0-9][0-9][0-9][.] -o |sort -u
````


# dar static tip
  The script now backs up the /usr/bin/dar_static executable with your archives, if the static version is found.

  If you at some point in the future need to extract files from the archive, you know you have correct binary at hand.


# Exit values
| #   | Description |
| --- | ----------- |
| 0 | script ended without errors |
| 1 | script exited with an error |
| 100 | FULL backup not found |


# shared, not installed
## systemd user timer & service

An example of a timer and service for installation in the user's systemd directory is provided

# Version
## dar-backup script
  The script has reached version 1.0 - I trust it.

## 'dar' itself
My ubuntu 21.04 currently gives me this:
````
~ dar --version

 dar version 2.6.13, Copyright (C) 2002-2020 Denis Corbin
   Long options support         : YES

 Using libdar 6.2.7 built with compilation time options:
   Libz compression (gzip)      : YES
   Libbz2 compression (bzip2)   : YES
   Liblzo2 compression (lzo)    : YES
   Liblzma compression (xz)     : YES
   Strong encryption (libgcrypt): YES
   Public key ciphers (gpgme)   : YES
   Extended Attributes support  : YES
   Large files support (> 2GB)  : YES
   ext2fs NODUMP flag support   : YES
   Integer size used            : 64 bits
   Thread safe support          : YES
   Furtive read mode support    : YES
   Linux ext2/3/4 FSA support   : YES
   Mac OS X HFS+ FSA support    : NO
   Detected system/CPU endian   : little
   Posix fadvise support        : YES
   Large dir. speed optimi.     : YES
   Timestamp read accuracy      : 1 microsecond
   Timestamp write accuracy     : 1 microsecond
   Restores dates of symlinks   : YES
   Multiple threads (libthreads): NO 
   Delta compression support    : NO
   Remote repository support    : NO
````
I can confirm large file support works. At one point I mistakenly omitted slices, and an archive ~550 GB was created, tested + a single file restore was performed. Kudos to dar, par2 and the ubuntu servers that hosted the archive :-).


# TODO
  - An INC backup checks if a previous DIFF has been made. It doesn't care if a newer FULL has been created.
  - Currently INC backups are relative the latest DIFF - that makes it easy to restore.  Incremental backups are usually relative to the latest backup taken (whatever type), in order to make them as small as possible. Hmm, need to decide on the best way forward.
  - Scheduled verifications of old archives, to  detect bit rot on storage media, could be useful

# Projects this script benefits from
 1. [The wonderful dar achiver](https://github.com/Edrusb/DAR)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [shellcheck - a bash linter](https://github.com/koalaman/shellcheck)
 4. [Ubuntu of course :-)](https://ubuntu.com/)

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html

