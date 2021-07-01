
# Full backups + differential backups using 'dar'

  The wonderful 'dar' (Disk Archiver) (https://dar.sourceforge.io/) is used for 
  the heavy lifting in these scripts.

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
  - Test the archive after backup
  - Simple restore test, restoring 1 file to feel more confident about the backup
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
  - make the install.sh script executable and run it
    ````
    chmod +x install.sh
    ./install.sh
    ````
  - Define backups in the "backups.d" directory, just drop files in the directory
  
    Open one of the demo backups.d/ files, alter the 5 variables to your taste    
    - BACKUP_NAME=TEST
    - FS_ROOT=~/tmp/test
    - TESTRESTORE_PATH=/tmp
    - EXCLUDES="DIR WITH SPACE;ANOTHER DIR WITH SPACE"
    - INCLUDES="first dir;second dir"

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
  
## how to restore a directory
  I do a "list" and "grep" like this
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  Rememeber that the archive name is without "slice_number.dar"
  Once I have located the directory to restore, do like this (here the restore is below /tmp)
  ````
  dar  -x ~/path/to/archive -R /tmp -p <the directory you want to restore>
  ````
## how to restore a single file
  Much like restoring a directory, I seek out the file with a "list" and "grep"
  ````
  dar -l /path/to/archive |grep "your search string"
  ````
  and the tell dar to go into (-g) a specific directory and restore the specific file (to /tmp in this example)
  ````
  dar -x /path/to/archive -R /tmp -g path/to/directory/in/archive/  -I file_to_restore
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
  It is a very good idea to stash the /usr/bin/dar_static executable with your archives.
  If you at some point in the future needs to extract files from the archive, you know you have correct binary at hand.

# Issues
## Building list of directories to exclude
  I have spent a fair amount of time building the list of directories to exclude. In the end I was unable to build a commandline without single quote characters surrounding the string, so I ended up with building a script in /tmp and executing it.

  I am clearly not versed well enough in the intricacies of parameter expanding :-(

# Version

  Consider this working, but not battletested. It is perhaps something like version 0.9'ish.

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html

