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
  systemctl --user daemon-reload
  ````
  - verify your timer is listed, and that the "NEXT" time is correct

  ````
  systemctl --user list-timers
  ````
### View systemd status

  ````
  systemctl --user status dar-backup.service
  ````


### view systemd log

  - View systemd messages 
  ````
  journalctl --user -u dar-backup.service
  ````

  - View systemd messages for a time period
  ````
  journalctl --user -u dar-backup.service --since "2022-04-13 08:00:00"  --until "2022-04-13 09:00:00"
  ````



### systemd documentation

  - [systemd website](https://systemd.io/)
  - [systemd timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
  - [systemd service (unit)](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)
  