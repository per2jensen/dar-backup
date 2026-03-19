# systemd Setup

Back to [README](../../README.md)

## Generate systemd files

The command `dar-backup-systemd` can generate and optionally install systemd units and timers.

The timers are set as the author uses them, modify to your taste and needs.

Example run:

```bash
dar-backup-systemd --venv /home/user/tmp/venv --dar-path /home/user/.local/dar/bin
Generated dar-full-backup.service and dar-full-backup.timer
  → Fires on: *-12-30 10:03:00
Generated dar-diff-backup.service and dar-diff-backup.timer
  → Fires on: *-*-01 19:03:00
Generated dar-incr-backup.service and dar-incr-backup.timer
  → Fires on: *-*-04/3 19:03:00
Generated dar-clean.service and dar-clean.timer
  → Fires on: *-*-* 21:07:00
```

## Systemctl examples

dar-backup is scheduled to run via systemd --user settings.

The files are located in: `~/.config/systemd/user`

Once the .service and .timer files are in place, timers must be enabled and started.

```` bash
systemctl --user enable dar-inc-backup.timer
systemctl --user start  dar-inc-backup.timer
systemctl --user daemon-reload
````

Verify your timers are set up as you want:

```bash
systemctl --user list-timers
```

## Service example: dar-backup --incremental-backup

File:  dar-incr-backup.service

```bash
/tmp/test$ dar-backup-systemd --venv '$HOME/programmer/dar-backup.py/venv'  --dar-path '$HOME/.local/dar/bin'

Generated dar-full-backup.service and dar-full-backup.timer
  → Fires on: *-12-30 10:03:00
Generated dar-diff-backup.service and dar-diff-backup.timer
  → Fires on: *-*-01 19:03:00
Generated dar-incr-backup.service and dar-incr-backup.timer
  → Fires on: *-*-04/3 19:03:00
Generated dar-cleanup.service and dar-cleanup.timer
  → Fires on: *-*-* 21:07:00
/tmp/test$
(venv) /tmp/test$
(venv) /tmp/test$ cat dar-incr-backup.service
[Unit]
Description=dar-backup INCR
StartLimitIntervalSec=120
StartLimitBurst=1

[Service]
Type=oneshot
TimeoutSec=infinity
RemainAfterExit=no


ExecStart=/bin/bash -c 'PATH=$HOME/.local/dar/bin:$PATH && . $HOME/programmer/dar-backup.py/venv/bin/activate && dar-backup -I --verbose --log-stdout'
```

## Timer example: dar-backup --incremental-backup

File:  dar-incr-backup.timer

```text
[Unit]
Description=dar-backup INCR timer

[Timer]
OnCalendar=*-*-04/3 19:03:00
Persistent=true

[Install]
WantedBy=timers.target
```

## systemd timer note

OnCalendar syntax is flexible — you can tweak backup schedules easily. Run `systemd-analyze calendar` to preview timers.
