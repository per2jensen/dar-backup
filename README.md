
# Table of contents

- [Full, differential or incremental backups using 'dar'](#full-diff-inc)
- [My use case](#my-use-case) 
- [Inspiration](#inspiration) 
- [How to install](#how-to-install) 
- [Script features](#script-features) 
- [Requirements](#requirements) 
- [Invocation](#invocation)
- [Options](#options)  
- [How to use](#how-to-use) 
- [darrc](#darrc) 
- [Examples](#examples) 
  - [default to not mount a remote directory](#default-to-not-mount-remote-dir)
  - [how to run a single backup definition](#run-a-single-definition) 
  - [how to test that the archive is healthy](#test-archive) 
  - [how to restore a directory](#restore-dir) 
  - [how to restore a single file](#restore-file)
  - [how to restore firefox snap](#restore-firefox-snap) 
  - [restore test fails with exit code 4](#restore-test-exit-code-4) 
  - [restore test fails with exit code 5](#restore-test-exit-code-5) 
  - [par2 verification/repair](#par2-verification)</a>  
  - [par2 create redundency files](#par2-redundency)</a> 
  - [performance tip](#performance-tip) 
  - [overview of archives](#overview-of-archives) 
  - [merge FULL with DIFF, creating new FULL](#merge-full-diff)
  - [cleanup a usbdisk for old archives](#cleanup-usbdisk) 
  - [verbosity](#verbosity) 
  - [trim the log file ](#trim-log-file) 
- [list all dar archives, sorted on slice number](#list-sort-slice-no) 
- [dar static tip](#static-dar) 
- [ Exit values](#exit-codes)
- [Systemd stuff (not installed by default)](https://github.com/per2jensen/dar-backup/tree/main/share) 
- [Version](#version) 
- [TODO](#todo)
- [Successful restores](#success-restores)
- [Projects this script benefits from](#dependencies)
- [License](#license) 


# <a id="full-diff-inc"> Full, differential or incremental backups using 'dar' 

  The wonderful 'dar' [Disk Archiver] (https://github.com/Edrusb/DAR) is used for 
  the heavy lifting, together with the par2 suite in these scripts.

# <a id="license"> License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html, or have a look at the ["LICENSE"](https://github.com/per2jensen/dar-backup/blob/main/LICENSE) file in this repository.

# Github location
This 'dar-backup' package lives at: https://github.com/per2jensen/dar-backup

# <a id="my-use-case"> My use case

 I have cloud storage mounted on a directory within my home dir. The filesystem is [FUSE based](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), which gives it a few special features
 - a non-privileged user (me :-)) can perform a mount
 - a privileged user cannot look into the filesystem --> a backup script running as root is not suitable

 I needed the following:
 - Backup my cloud storage to something local (cloud is convenient, but I want control over my backups)
 - Backup primarily photos, video and different types of documents
 - Have a simple non-complicated way of restoring, possibly years into the future. 'dar' fits that scenario with a single statically linked binary (kept with the archives). There is no need install/configure anything - restoring is simple and works well.
 - During backup archives must be tested and a restore test (however small) performed
 - Archives stored on a server with a reliable file system (easy to mount a directory over sshfs)
 - Easy to verify archives' integrity, after being moved around.

 I do not need the encryption features of dar, as all storage is already encrypted.
 

# <a id="inspiration"> Inspiration

  I have used 'dar' before, and is now back. Thank you Denis Corbin for a great
  backup solution and for 20+ years of work/support. Outstanding!

  The dar mini-howto has been inspirational, it is a very good read, kudos to 
  Grzegorz Adam Hankiewicz
  https://dar.sourceforge.io/doc/mini-howto/dar-differential-backup-mini-howto.en.html


  These are some of the features and workflows, that are plusses in my book:
  
  - 'dar' itself is rock solid and has been for years, it truly is a great tool. Don't think this is another 'tar', it is way better.

  - I like being able to verify that an archive is good, once it has been stored remotely. When I copy the archives from the server to somewhere else, I am again able to verify that the archive is healthy.

  - par2 files provides a method to maybe salvage a broken archive in the future.

# <a id="how-to-install"> How to install
  - Download a dar-backup tar file from the [releases](https://github.com/per2jensen/dar-backup/releases)
  - untar 
    ````
    UNTAR_LOCATION=<a-directory-under-which-darbackup-is-untarred>
    tar zxf <the-tar-file> --directory "$UNTAR_LOCATION"
    ````
  - make install script executable
    ````
    chmod +x "$UNTAR_LOCATION"/dar-backup/bin/install.sh
    ````
  - Run install.sh
    ````
    "$UNTAR_LOCATION"/dar-backup/bin/install.sh
    ````

  - Take a backup of the installation
    ````
    "$UNTAR_LOCATION"/dar-backup/bin/dar-backup.sh --local-backup-dir
    ````

  - View the log file
    ````
    cat "$UNTAR_LOCATION"/dar-backup/archives/dar-backup.log
    ````
    During installation, a directory has been created "<a-directory-under-which-darbackup-is-untarred>/dar-backup/archives", where the backups have been stored.


  All files stay where untarred, when running the installer.
  
  The installer makes scripts executable, creates soft links, sets up references to the various config files used.
  The install also generates systemd service files, which can be put in ~/.config/systemd/user/ (they are not deployed).

  Once installed:
  
  - Have a look at config file in conf/, and tweak it to your needs
  - Then create a backup definition in backups.d/, using the "dar-backup" file as your starting point.

# <a id="script-features"> Script features

  - Take full backups, differential backups or incremental backups
  - Uses par2 for file repair, 5% error correction configured
    - As an example 3 8K blocks bitrot introduced in a test archive is repairable. That amounts to just about 5% bitrot (see [testcase1](https://github.com/per2jensen/dar-backup/blob/main/test/test-parchive.sh), [testcase2](https://github.com/per2jensen/dar-backup/blob/main/test/test-parchive-multiple-8k-blocks.sh)) 
    - See more on integration to [parchive](http://dar.linux.free.fr/doc/usage_notes.html#Parchive)
  - Test the archive after a backup
  - Search for a file < 10MB, and restore it under /tmp as part of the backup verification
  - Copies dar_static to server (handy to have the statically linked binary available in the future)
  - Simple to add backups, including directories to include and to exclude in each backup definition
  - Run a single backup definition from backups.d/
  - Systemd services and schedules generated when installing, ready to be dropped into ~/.config/systemd/user (see [share/](https://github.com/per2jensen/dar-backup/tree/main/share)). The following is generated:
    - FULL backup
    - DIFF backup
    - INC backup
    - Cleanup
  - sshfs *can* be used to mount remote directory (this was previously hard coded into the script)
    - sshfs uses [FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html), allowing a non-privileged user to mount remote storage.
  - Logs to a logfile in a user configured directory
  - Can save all output to a debug log file, handy if dar exit code is 5 (number files not backed up are listed)
  - Status messages can be sent to a Discord hook, change the sendDiscordMsg() function to suit your needs
  - Cleanup script removes DIFFs older than 100 days, and INCs older than 40 days. FULL backups are not touched.
  - Test cases: verify backups work, the installer, parchive error correction, cleanup and more on every commit via Githup Actions

# <a id="requirements"> Requirements
  - sshfs (if mounting a server directory)
  - dar
  - par2
  - curl

  On Ubuntu, install the requirements this way:
  ````
    sudo apt install sshfs dar dar-static par2 curl
  ````

# <a id="invocation"> Invocation

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

# <a id="options">  Options

  The script has a few options to modify it's behavior:

##  --backupdef definition

  Run only a single backup definition, instead of all definitions kept in the backups.d directory

  'definition' is one of the filenames in backups.d/

## --debug
  Make bash print all statements via the "set -x" option. Save output to debug log file.

## --fsa-scope-none

  If you encounter restore errors due to file system incompatibility on file attributes, use this option when restoring.

  The issue might arise if you backup files on an ext4 file system, and for example restore to an Apple file system.

  See more in the section on [restore exit code 5](#fsa-scope-none)

## --help

  Terse usage information

## --local-backup-dir

  Make the script bypass mounting a remote server directory using sshfs. The backup archives are stored in the "MOUNT_POINT" config setting. This directory can of course be mounted by some other method :-)

# --run-restore-test archive
  If you for some reason need to rerun a restore test from an existing archive, use this option.
  'archive' is the dar archive name without ".<slice#>.dar"

  dar-backup expects the archive to be located at the path set in MOUNT_POINT in the config file.

## --verbose
  More chatty log messages written to log file and sent to Discord

  Without the option the log file is much more lean and easy to glance over, to see the status of a backup run.

## --version
  Prints the release number or the substitution variable if it is a development version.


# <a id="how-to-use"> How to use
  
  I use Ubuntu on my workstation, so this script is a 'bash' script. The 'dar' program is from the Ubuntu package, I also have par2 installed.

  Although I use the sshfs mount method, you don't need to. Use the "--local-backup-dir" option to bypass the server mount.
  Also I have set up a Discord account that receives messages, it is easy to change that in the sendDiscordMsg() function.

  The recipe for me to get this script running is the following:   

  - Setup an ssh access using a key for logging into the server
  - A Discord webhook is needed for the messages to be sent
  - A 'darrc' file is generated in the conf dir, once the install.sh script has been run.
    It controls which files not to compress
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

      # age in days for DIFF archives to be cleaned up (deleted)
      DIFF_AGE=100

      # age in days for INC archives to be cleaned up (deleted)
      INC_AGE=40
    ````
  - Define backups in the "backups.d" directory, just drop files in the directory
  
    Alter the demo backups.d/dar-backup file to your taste
  
    
````

      # definition to backup the deployed version

      # ===========================================
      # @@CONFDIR@@ is replaced at install time
      # ===========================================

      # Include defaults
      -B "@@CONFDIR@@/defaults-rc"

      # Switch to ordered selection mode, which means that the following
      # options will be considered top to bottom
      -am

      # Backup Root dir
      -R "@@CONFDIR@@/../.."

      # Directories to backup below the Root dir
      -g dar-backup

      # Directories to exclude below the Root dir
      -P dar-backup/archives
      
      # compression level
      -z5

      # no overwrite, if you rerun a backup, 'dar' halts and asks what to do
      -n
      
      # size of each slice in the archive
      --slice 4G

      # bypass directores marked as cache directories
      # http://dar.linux.free.fr/doc/Features.html
      --cache-directory-tagging

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

# <a id="darrc"> darrc
  The scripts do not use ~/.darrc nor do they use /etc/darrc

  The defaults used by the scripts (for example file types not to compress) are linked by backup definitions. The defaults are stored in conf/defaults-rc.

  The demo backup definition templates/backups.d/dar-backup links defaults-rc in the first directive.

# <a id="examples"> Examples

## <a id="default-to-not-mount-remote-dir"> default to not mount a remote directory
  By default dar-backup expects to mount a remote directory using sshfs, to save archives there.
  
  That might not be your use case, you might want to use a directory already mounted, or a local disk on your machine. You have two options to bypass the sshfs mount.

  1.  Use the option "--local-backup-dir" option on the command line, which tells dar-backup not to do a mount.

  2.  Put the environment variable LOCAL_BACKUP_DIR in the conf/dar-backup.conf file like this:
  ````
  LOCAL_BACKUP_DIR=1
  ````
  This way you will not need to use the --local-backup-dir option, it is set as a default for all scrips in the dar-backup package.

## <a id="run-a-single-definition"> how to run a single backup definition
  Backup definitions are placed in the backups.d/ directory. Each definition corresponds to a separate 'dar' archive.
  By default the dar-backup.sh loops over all definitions and runs the specified backups.

  If you want to just run a single backup definition, do it like this:
  ````
  dar-backup.sh -d "the definition"
  ````
  where "the definition" is the filename in backups.d/
  
## <a id="test-archive"> how to test that the archive is healthy
  If you have copied the archive somewhere, it gives peace of mind to know the archive is still healthy.
  ````
  dar -vd -t <the archive>
  ````
  Remember that the archive name is without "slice_number.dar"

  Another way to verify the archives is to use [par2 verification](#par2-verification)

## <a id="restore-dir"> how to restore a directory
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



## <a id="restore-file"> how to restore a single file
  Much like restoring a directory, I seek out the file with a "list" and "grep"
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  and the tell dar to go into (-g) a specific directory and restore the specific file
  ````
  dar -x /path/to/archive -R /tmp -g path/to/directory/in/archive/file_to_restore
  ````
  
  The "-I" option works on the file name only, and not path/file-name as the "-g" option. So using "-I" could select and restore more than one file in a directory tree.

## <a id="restore-firefox-snap"> how to restore firefox snap

  I'm using the supplied Ubuntu 22.04 firefox snap package. It doesn't do everything I want it to,
  but I try to use the supplied version if it works for me. Over time that leads to fewer hassles.

  I have done a test restore of the snap, to see if I can restore firefox snap and get a working browser with all bookmarks intacts. I could :-), here is the procedure I followed:
   
  - Restore the snap to /tmp
  - First restore the FULL archive (no snap there)
  - Then restore the latest DIFF, using -wa option in case overwriting files was necessary.
  - Lastly restore the latest INC,  using -wa option in case overwriting files was necessary.
  - Make sure firefox is closed
  - Move the working snap away
  - Move the restored firefox snap to ~/snap
  - Test firefox
  - Make sure firefox is closed
  - Delete the restored snap
  - Move working snap back

  ````
  dar -x mnt/dar/pj_homedir_FULL_2022-01-08 -R /tmp -g snap/firefox

  dar -x mnt/dar/pj_homedir_DIFF_2022-06-25 -R /tmp -g snap/firefox -wa

  dar -x mnt/dar/pj_homedir_INC_2022-07-22  -R /tmp -g snap/firefox -wa

  killall firefox

  mv ~/snap/firefox ~/snap/firefox-org

  mv /tmp/snap/firefox ~/snap/

  firefox

  killall firefox

  rm -fr ~/snap/firefox

  mv ~/snap/firefox-org ~/snap/forefox
  ````
  
## <a id="restore-test-exit-code-4"> restore test fails with exit code 4
  "dar" in newer versions emits a question about file ownership, which is "answered" with a "no" via the "-Q" option. That in turn leads to an error code 4.

  Thus the dar option "--comparison-field=ignore-owner" has been placed in the defaults-rc file. This causes dar to restore without an error. It is a good option when using dar as a non-privileged user. 

## <a id="restore-test-exit-code-5"> <a id="fsa-scope-none"> restore test fails with exit code 5
  If exit code 5 is emitted on the restore test, FSA (File System specific Attributes) could be the cause.

  That (might) occur if you backup a file stored on one type of filesystem, and restore it on another type.
  My home directory is on a btrfs filesystem, while /tmp (for the restore test) is on zfs.

  The restore test can result in an exit code 5, due to the different filesystems used. In order to avoid the errors, the "option "--fsa-scope none" can be used. That will restult in FSA's not being restored.

  Use the dar-backup option --fsa-scope-none to avoid this type of error.

## <a id="par2-verification"></a>  par2 verification/repair

### Use parchive solo
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

### Use par parchive integration
You can also use dar's slice functionality to verify slices using parchive:
````
dar -t <archives-path>/<the-archive> -E '<dar-backup install path>/bin/dar_par_test.duc  "%p" "%b" "%N" "%e" "%c"'
````
This example verifies an archive from the test/test-backup.sh script:
````
dar -t /tmp/dar-backup-test/archives/TEST_FULL_2022-07-13 -E '/tmp/dar-backup-test/bin/dar_par_test.duc  "%p" "%b" "%N" "%e" "%c"'

par2 verification slice /tmp/dar-backup-test/archives/TEST_FULL_2022-07-13.1.dar...
Loading "TEST_FULL_2022-07-13.1.dar.par2".
Loaded 4 new packets
Loading "TEST_FULL_2022-07-13.1.dar.vol00+99.par2".
Loaded 99 new packets including 99 recovery blocks

There are 1 recoverable files and 0 other files.
The block size used was 348 bytes.
There are a total of 1983 data blocks.
The total size of the data files is 690027 bytes.

Verifying source files:

Opening: "TEST_FULL_2022-07-13.1.dar"
Target: "TEST_FULL_2022-07-13.1.dar" - found.

All files are correct, repair is not required.


 --------------------------------------------
 7 item(s) treated
 0 item(s) with error
 0 item(s) ignored (excluded by filters)
 --------------------------------------------
 Total number of items considered: 7
 --------------------------------------------

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
  
## <a id="performance-tip"> performance tip
  This [dar benchmark page](https://dar.sourceforge.io/doc/benchmark.html) has an interesting note on the slice size.
  
  Slice size should be smaller than available RAM, apparently a large performance hit can be avoided keeping the the par2 data in memory.
  
## <a id="overview-of-archives"> overview of archives
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

## <a id="cleanup-usbdisk"> clean up a usbdisk for old archives
  I copy dar achives from my server to different usbdisks, which are rotated out of my home.
  That provides increased redundency and increases the chances of recovery in the event, that all computers are stolen or my home burns down to the ground.

  The cleanup script can be used to remove old archives located anywhere on the file system. It uses the DIFF_AGE and INC_AGE settings from the [configuration file](https://github.com/per2jensen/dar-backup/blob/main/templates/dar-backup.conf.template) when cleaning up.

  The option --alternate-archive-dir is used, most commonly together with the --local-backup-dir option. An example can be seen in the [testscript](https://github.com/per2jensen/dar-backup/blob/main/test/test-cleanup-alternate-dir.sh)

  For this example, let's assume that a usbdisk with dar archives has been mounted on /media/pj/usbdisk. In order to cleanup old archives on the usbdisk, do the following
  
  ````
  <dar-backup>/bin/cleanup.sh --local-backup-dir --alternate-archive-dir "/media/pj/usbdisk"
  ````
  
  The log messages are written to the logfile configured in the config file.


## <a id="merge-full-diff"> merge FULL with DIFF, creating new FULL
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

## <a id="verbosity"> verbosity
The file conf/defaults-rc contains various verbosity settings, that can be enabled by removing the "#" char. A brief explanation to each option is provided.

## <a id="trim-log-file"> trim the log file 
  'dar' notes every directory is has processed, that can clutter the log file. If you want to trim the log file after the fact, try this:
  ````
  # remove lots of directory notices from the log file
  sed -i '/^Inspecting directory/d' ~/dar-backup.log
  
  # remove more directory notices from the log file
  sed -i '/^Finished Inspecting/d' ~/dar-backup.log 
  ````   

## <a id="list-sort-slice-no"> list all dar archives, sorted on slice number
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


# <a id="static-dar"> dar static tip
  The script now backs up the /usr/bin/dar_static executable with your archives, if the static version is found.

  If you at some point in the future need to extract files from the archive, you know you have correct binary at hand.


# <a id="exit-codes"> Exit values
| #   | Description |
| --- | ----------- |
| 0 | script ended without errors |
| 1 | script exited with an error |


# <a id="systemd-files"> Systemd stuff (not installed by default)

Plug in timers and service files can be found in the [shared section](share/README.md)

# <a id="version"> Version
## dar-backup script
  The script has reached version 1.0 - I trust it.

## 'dar' itself

My ubuntu 22.04 currently gives me this:

````
dar --version

 dar version 2.7.3, Copyright (C) 2002-2022 Denis Corbin
   Long options support         : YES

 Using libdar 6.4.2 built with compilation time options:
   gzip compression (libz)      : YES
   bzip2 compression (libbzip2) : YES
   lzo compression (liblzo2)    : YES
   xz compression (liblzma)     : YES
   zstd compression (libzstd)   : YES
   lz4 compression (liblz4)     : YES
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
   Linux statx() support        : YES
   Detected system/CPU endian   : little
   Posix fadvise support        : YES
   Large dir. speed optimi.     : YES
   Timestamp read accuracy      : 1 nanosecond
   Timestamp write accuracy     : 1 nanosecond
   Restores dates of symlinks   : YES
   Multiple threads (libthreads): NO 
   Delta compression (librsync) : NO
   Remote repository (libcurl)  : NO
   argon2 hashing (libargon2)   : YES

````
I can confirm large file support works. At one point I mistakenly omitted slices, and an archive ~550 GB was created, tested + a single file restore was performed. Kudos to dar, par2 and the ubuntu servers that hosted the archive :-).


# <a id="todo"> TODO

  - Use [dar manager](http://dar.linux.free.fr/doc/Tutorial.html) database to ease restores of specific files.
  - Only 1 "REMOVED ENTRY" if a file+dir has been removed. See example in test/test-saved-removed.sh
  - Scheduled verifications of old archives, to  detect bit rot on storage media, could be useful

# <a id="success-restores"> Successful restores :-)

  **2022-09-02** 

  My ~/snap/firefox directory had vanished, I think due to installing firefox from the Mozilla website (installed due to boot issues caused by a full zfs /boot filled by snapshots).

  Before running the Mozilla download, I did a "dar-inc-backup.sh -d pj_homedir", which came in handy an hour later :-)

  I followed the [recipe to restore firefox snap](#restore-firefox-snap), and had my full firefox snap user files back in a few minutes. 
  
  'dar' really rocks!

# <a id="dependencies"> Projects this script benefits from

 1. [The wonderful dar achiver](https://github.com/Edrusb/DAR)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [shellcheck - a bash linter](https://github.com/koalaman/shellcheck)
 4. [Ubuntu of course :-)](https://ubuntu.com/)


