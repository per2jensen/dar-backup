# Misc stuff not installed

## systemd timer & service for DIFF backups

  A timer and service file is provided for use on linux systems with systemd, which can be deployed in a user's systemd directory.
  
### installation

  - edit the timer and set the time/frequency to your liking
  - edit the service and point to the location of the dar-diff-backup.sh script
  - copy the timer and service files to ~/.config/systemd/user/
  - install the files in systemd

  ````
  systemctl --user enable dar-backup.timer
  systemctl --user start  dar-backup.timer
  sudo systemctl daemon-reload
  ````
  - verify your timer is listed

````
  systemctl --user list-timers
  ````
