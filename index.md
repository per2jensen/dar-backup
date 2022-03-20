<script>
(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
})(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

ga('create', 'UA-XXXXX-Y', 'auto');
ga('send', 'pageview');
</script>
<!-- End Google Analytics -->


# Full, differential and incremental backups using 'dar' 

  The wonderful 'dar' (Disk Archiver) (https://github.com/Edrusb/DAR) is used for 
  the heavy lifting, together with the par2 suite in these scripts.

# Version 1.0 released
v1.0 was released on February 13, 2022 after having been my trusted backup solution since summer 2021. 


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

# Script features

  - Take full, differential and incremental backups
  - Uses the par2 functionality for file repair, 5% error correction configured
    http://dar.linux.free.fr/doc/usage_notes.html#Parchive 
  - Test the archive after backup
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

# How to install
  - Download a dar-backup tarball from the (releases)[https://github.com/per2jensen/dar-backup/releases] 

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
    
  The programs stay where untarred when running the installer, it makes the scripts executable, creates a soft link and sets up references to the various config files used.  

  During installation, a directory has been created "<a-directory-under-which-darbackup-is-untarred>/dar-backup/archives", where the backups have been stored (change config to your preferred location).


# dar-backup source code

The Github source code repository is here: [dar-backup on Github](https://github.com/per2jensen/dar-backup)
