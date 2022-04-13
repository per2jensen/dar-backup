  # Systemd backup schedule

## Systemd timers & services

  Systemd timers and service files for FULL, DIIF and INC backups can be found in the share/ directory.
  "
  The files are ready to be copied by the user to "~/.config/systemd/user"

  The timers have been setup like this:

    - FULL backup on December 30 10:03:00
    - DIFF backups on the first day of a month (including Jan) 19:03:00
    - INC backups starting on the fouth day of a month 19:03:00, repeating every 3 days
  
### Installation

  - copy the "share/*.timers" &  "share/*.service" to ~/.config/systemd/user/
  - install the files in systemd

  ````
  cp <dar-backup>/share/*.{timer|service} ~/.config/systemd/user/ 
  systemctl --user enable dar-backup.timer
  systemctl --user start  dar-backup.timer
  
  systemctl --user enable dar-diff-backup.timer
  systemctl --user start  dar-diff-backup.timer
  
  systemctl --user enable dar-inc-backup.timer
  systemctl --user start  dar-inc-backup.timer
  
  systemctl --user daemon-reload
  ````
  - verify your timers are listed, and that the "NEXT" time is correct for each timer

  ````
  systemctl --user list-timers
  ````

### View systemd status
  Do this to view systemd status for your services

  ````
  systemctl --user status dar-backup.service
  systemctl --user status dar-diff-backup.service
  systemctl --user status dar-inc-backup.service
  ````

### View systemd log

  - View systemd messages for the FULL service
  ````
  journalctl --user -u dar-backup.service
  ````

  - View systemd messages for a time period for the FULL service
  ````
  journalctl --user -u dar-backup.service --since "2022-04-13 08:00:00"  --until "2022-04-13 09:00:00"
  ````


### Systemd documentation

  - [systemd website](https://systemd.io/)
  - [systemd timer](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
  - [systemd service (unit)](https://www.freedesktop.org/software/systemd/man/systemd.unit.html)

