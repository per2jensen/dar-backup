
# Full backups + differential backups using 'dar'

  The wonderful 'dar' (Disk Archiver) (https://dar.sourceforge.io/) is used for 
  the heavy lifting, together with the par2 suite in these scripts.

# Inspiration

  I have used 'dar' before, and is now back. Thank you Denis Corbin for a great
  backup solution and for 20+ years of work/support. Outstanding!

  The dar mini-howto has been inspirational, it is a very good read, kudos to 
  Grzegorz Adam Hankiewicz
  https://dar.sourceforge.io/doc/mini-howto/dar-differential-backup-mini-howto.en.html


  These are some of the features and workflows, that are plusses in my book:
  
  - 'dar' itself is rock solid and has been for years, it truly is a great tool. Don't think this is another 'tar', it is way better.

  - I like being able to verity that an archive is good, once it has been stored remotely. When I copy the archives from the server to somewhere else, I am again able to verify that the archive is healthy.

  - The built in par2 integration provides a method to maybe be able to salvage a broken archive in the future.

# Script features

  - Take full backups or differential backups
  - Uses the par2 functionality for file repair, 5% error correction configured
    http://dar.linux.free.fr/doc/usage_notes.html#Parchive 
  - Test the archive after 
  - Tries to find a file < 10MB, and restores it under /tmp
  - Copies dar_static to server
  - Simple to add backups, including directories to include and to exclude in each backup
  - Run a single backup definition from backups.d/
  - sshfs *can* be used to mount remote directory (this was previously hard coded into the script)
    an ssh key setup has to be in place for the automatic mount
  - Logs to a logfile in a user configured directory
  - Can save all output to a debug log file, handy if dar exit code is 5 (number files not backed up are listed)
  - Status messages are sent to a Discord hook, change the sendDiscordMsg() function to suit your needs
  - Improved testing: an automatic backup test is now performed on every commit using Githup actions

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

## --dry-run

  Run 'dar' in dry run mode, to see what would have been backed up.

##  --backupdef definition

  Run only a single backup definition, instead of all definitions kept in the backups.d directory

  'definition' is one of the filenames in backups.d/

## --local-backup-dir

  Make the script bypass mounting a remote server directory using sshfs. The backup archives are stored in the "MOUNT_POINT" config setting. This directory can of course be mounted by some other method :-)

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
      # the Discord webhook address to send messages to
      DISCORD_WEBHOOK="the long Discord webhook here"

      # server name or ip address
      SERVER=your_server

      # the directory on the server used to store backups
      SERVER_DIR=/some/dir

      # where to mount the sshfs mount
      # if the --local-backup-dir option is set, ths sshfs mount is not performed
      MOUNT_POINT=~/another_dir

      # path to log file
      LOG_LOCATION=/directory/name/
      
      # should all output be captured in a file
      # any other characted than "y" means no
      DEBUG=y
      
      # path to debug log file
      DEBUG_LOCATION=/some/dir/dar-debug.log

    ````
  - Define backups in the "backups.d" directory, just drop files in the directory
  
    Open the demo templates/backups.d/TEST files, alter the variables to your taste

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

# Examples

# how to run a single backup definition
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

## how to restore a directory
  I do a "list" and "grep" like this
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  Remember that the archive name is without "slice_number.dar"
  Once I have located the directory to restore, do like this (here the restore is below /tmp)
  ````
  dar  -x ~/path/to/archive -R /tmp -p <the directory you want to restore>
  ````
## how to restore a single file
  Much like restoring a directory, I seek out the file with a "list" and "grep"
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  and the tell dar to go into (-g) a specific directory and restore the specific file (-I) (to /tmp in this example)
  ````
  dar -x /path/to/archive -R /tmp -g path/to/directory/in/archive/  -I file_to_restore
  ````

## par2 verification/repair
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
## overview of archives
Once you har a fair amount of archives, it can become a bit hard to have an overview of what's there.
One way to get an overview is to use the 2 scripts "show-FULL.sh" and "show-DIFF.sh"
````
./show-FULL.sh 
Mountpoint: /home/pj/mnt/dar
dba_FULL_2021-06-27            slices: 1    
media-files_FULL_2021-06-27    slices: 46   
ws_FULL_2021-06-30             slices: 1    
cloudDrive_FULL_2021-06-06     slices: 18   
pj_homedir_FULL_2021-06-06     slices: 7  
````
If you see a FULL archive that is significantly smaller than a previous one (i.e. fewer slices), you should probably find out why that is. There may be good reasons like:
 
  - You have cleaned up
  - The backup definition has more excludes

It could also be an error, so it is good to know why archive sizes change over time.

## merge FULL with DIIF, creating new FULL
  Over time, the DIFF archives become larger and larger. At some point one wishes to create a new FULL archive to do DIFF's on.
  One way to do that, is to let dar create a FULL archive from scratch, another is to merge a FULL archive with a DIFF, and from there do DIFF's until they once again gets too large for your taste.
  
  I do backups of my homedir. Here it is shown how a FULL archive is merged with a DIFF, creating a new FULL archive.
  ````
  dar --merge pj_homedir_FULL_2021-09-12  -A pj_homedir_FULL_2021-06-06  -@pj_homedir_DIFF_2021-08-29 -s 12
  ````
  
  **Notes**
  
  1. I tried to use an overwriting policy using '--overwriting-policy "O*"' which made dar ask if it should overwrite some files (Yes, overwrite using data from the DIFF). I am not entirely sure how the merging works at this point (2021-09-12)
  2. I specified "-ak" to prevent decompressing/compressing - that didn't work, due to different compression types used in the 2 archives (it is a feature for a future version of dar though)
  
## trim the log file 
  'dar' notes every directory is has processed, that can clutter the log file. If you want to trim the log file after the fact, try this:
  ````
  # remove lots of directory notices from the log file
  sed -i '/^Inspecting directory/d' ~/dar-backup.log
  
  # remove more directory notices from the log file
  sed -i '/^Finished Inspecting/d' ~/dar-backup.log 
  ````   
 

# dar static tip
  The script now backs up the /usr/bin/dar_static executable with your archives, if the static version is found.

  If you at some point in the future need to extract files from the archive, you know you have correct binary at hand.

# Issues

# Version
## dar-backup script
  Consider this working, but not battletested. It is perhaps something like version 0.9'ish.

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
# Projects this script benefits from
 1. [The wonderful dar achiver](https://dar.sourceforge.io/)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [Ubuntu of course :-)](https://ubuntu.com/)

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html

