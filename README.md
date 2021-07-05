
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
  - sshfs is used to mount remote directory --> thus this script cannot run as root
    an ssh key setup has to be in place for the automatic mount
  - logs to a logfile in a user configured directory
  - Status messages are sent to a Discord hook, change the sendDiscordMsg() function to suit your needs

# Requirements
  - sshfs
  - dar
  - par2
  - curl

  On Ubuntu, install the requirements this way:
  ````
    sudo apt install sshfs dar dar-static par2 curl
  ````

# How to use
  
  I use Ubuntu on my workstation, so this script is a 'bash' script. The 'dar' program is from the Ubuntu package, I also 
  have par2 installed.

  Although I use the sshfs mount method, it is simple add mount points in other ways, and modify the mountDar() function in dar-utils.sh to suit your needs. Also I have set up a Discord account that receives messages, it is easy to change that in the sendDiscordMsg() function.

  The recipe for me to get this script running is the following:   

  - Setup an ssh access using a key for logging into the server
  - A Discord webhook is needed for the messages to be sent
  - A 'darrc' file is generated in the conf dir, once the install.sh script has been run.
    It controls which files not to compress, ans points to the par2 configuration, also in
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
      MOUNT_POINT=~/another_dir
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
I can confirm large file support work. At one point I mistakenly omitted slices, and an archive ~550 GB was created, tested + a single file restore was performed. Kudos to dar, par2 and the ubuntu servers that hosted the archive :-).
# Projects this script benefits from
 1. [The wonderful dar achiver](https://dar.sourceforge.io/)
 2. [The Parchive suite](https://github.com/Parchive)
 3. [Ubuntu of course :-)](https://ubuntu.com/)

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html

