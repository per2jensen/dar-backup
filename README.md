
# Full backups + differential backups using 'dar'

  The wonderful 'dar' (Disk Archiver) (https://dar.sourceforge.io/) is used for 
  the heavy lifting in these scripts.

# Inspiration

  I have used 'dar' before, and is now back. Thank you Denis Corbin for a great
  backup solution and for 20+ years of work/support. Outstanding!

  The dar mini-howto has been inspirational, it is a very good read, kudos to 
  Grzegorz Adam Hankiewicz
  https://dar.sourceforge.io/doc/mini-howto/dar-differential-backup-mini-howto.en.html

# Script features

  - Take full backups or differential backups
  - Uses the par2 functionality for file repair 
    http://dar.linux.free.fr/doc/usage_notes.html#Parchive 
  - Test the archive after backup
  - Simple restore test, restoring 1 file to feel more confident in a good backup
  - Relatively simple to add more directories to backup
  - sshfs is used to mount remote directory --> this script cannot run as root
    an ssh key setup has to be in place for the automatic mount
  - Status messages are sent to a Discord hook, change the sendDiscordMsg() function to suit your needs

# Requirements
  - sshfs
  - dar
  - par2
  - curl

  On Ubuntu, install the requirements this way:
  ````
    sudo apt install sshfs dar par2 curl
  ````

# How to use
  
  I use Ubuntu on my workstation. The 'dar' program is from the Ubuntu package, I also 
  have par2 installed.

  - Setup an ssh access using a key for logging into the server
  - A Discord webhook is needed for the messages to be sent
  - Fill in some data in the dar-backup.conf file
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
  - make the script executable
    ````
    chmod +x dar-backup.sh
    ````
  - create a link for the "diff" program
    ````
    ln -s dar-backup.sh dar-diff-backup.sh
    ````
  - Open the script, set suitable values for these 3 variables
    
    - BACKUP_NAME=test
    - FS_ROOT=~/tmp/test
    - TESTRESTORE_PATH=/tmp
  - Execute the script and checkout the dar archive
    ````
    # do the backup
    .\dar-backup.sh
    
    # list the archive
    dar -l /PATH/TO/ARCHIVE 
    ````

# Version

  Consider this working, but not battletested. It is perhaps something like version 0.8'ish.

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html
