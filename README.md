
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
  - Uses the par2 functionality for file repair, 5% error correction configured
    http://dar.linux.free.fr/doc/usage_notes.html#Parchive 
  - Test the archive after backup
  - Simple restore test, restoring 1 file to feel more confident about the backup
  - Simple to add more directories to backup
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
    sudo apt install sshfs dar dar-static par2 curl
  ````

# How to use
  
  I use Ubuntu on my workstation. The 'dar' program is from the Ubuntu package, I also 
  have par2 installed.

  - Setup an ssh access using a key for logging into the server
  - A Discord webhook is needed for the messages to be sent
  - A 'darrc' file is generated in the conf dir, once the install.sh script has been run.
    It controls which files not to compress, ans points to the par2 configuration, also in
    conf dir
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
  - make the install.sh script executable and run it
    ````
    chmod +x install.sh
    ./install.sh
    ````
  - Define backups in the "backups.d" directory, just drop files in the directory
  
    Open the demo backups.d/TEST file, alter the 3 variables to your test    
    - BACKUP_NAME=TEST
    - FS_ROOT=~/tmp/test
    - TESTRESTORE_PATH=/tmp

  - Execute the script and "list" the dar archive to check that the backup is to your liking
    ````
    # do the backup
    .\dar-backup.sh
    
    # list the archive
    dar -l /PATH/TO/ARCHIVE |less
    ````

# dar static tip
  It is a very good idea to stash the /usr/bin/dar_static executable with your archives.
  If you at some point in the future needs to extract files from the archive, you know you have correct binary at hand.
# Version

  Consider this working, but not battletested. It is perhaps something like version 0.9'ish.

# License

  These scripts are licensed under the GPLv3 license.
  Read more here: https://www.gnu.org/licenses/gpl-3.0.en.html
