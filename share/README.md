# Systemd timers and services

  Systemd timers and service files can be found in the share/ directory.
  The following is here: 
  
    - FULL, DIFF and INC backups 
    - Alert sent on upcoming FULL & DIFF backups.

  The files are ready to be copied by the user to "~/.config/systemd/user"

## Grandfather, father, son backup strategy
  I use a variation of the [grandfather-father-son](https://en.wikipedia.org/wiki/Backup_rotation_scheme#Grandfather-father-son) backup strategy. The setup of backups detailed below is fitting for me, given the the current speed of changes to my filesystems.

  It is very easy to change the installed timers into a different variation of the backup strategy. I encourage you to always view the timer setup, as described below, after changes.


  The timers have been setup like this:

    - FULL backup on December 30 10:03:00
    - DIFF backups on the first day of a month (including Jan) 19:03:00
    - INC backups starting on the fourth day of a month 19:03:00, repeating every 3 days
  
## Installation

  - copy the "share/*.timers" &  "share/*.service" to ~/.config/systemd/user/
  - install the files in systemd

  ````
  cp <dar-backup>/share/*.timer ~/.config/systemd/user/ 
  cp <dar-backup>/share/*.service ~/.config/systemd/user/ 
  systemctl --user enable dar-backup.timer
  systemctl --user start  dar-backup.timer
  
  systemctl --user enable dar-diff-backup.timer
  systemctl --user start  dar-diff-backup.timer
  
  systemctl --user enable dar-inc-backup.timer
  systemctl --user start  dar-inc-backup.timer

  systemctl --user enable alert-upcoming-full-backup.timer
  systemctl --user start  alert-upcoming-full-backup.timer

  systemctl --user enable alert-upcoming-diff-backup.timer
  systemctl --user start  alert-upcoming-diff-backup.timer
  
  systemctl --user daemon-reload
  ````
  - verify your timers are listed, and that the "NEXT" time is correct for each timer

  ````
  systemctl --user list-timers
  ````

## View systemd status
  Do this to view systemd status for your services

  ````
  systemctl --user status dar-backup.service
  systemctl --user status dar-diff-backup.service
  systemctl --user status dar-inc-backup.service
  ````

## View systemd log

  - View systemd messages for the FULL service
  ````
  journalctl --user -u dar-backup.service
  ````

  - View systemd messages for a time period for the FULL service
  ````
  journalctl --user -u dar-backup.service --since "2022-04-13 08:00:00"  --until "2022-04-13 09:00:00"
  ````

## Example: run INC service & tail journal
  This example shows how to start the systemd "dar-inc-back.service" and view the status messages showing up in the systemd journal
  ````
  systemctl --user start dar-inc-backup.service

  journalctl --user -n 50 -f -u dar-inc-backup.service
  ````


# Systemd documentation

  - [systemd website](https://systemd.io/)
  - [systemd timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
  - [systemd service (unit)](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)

