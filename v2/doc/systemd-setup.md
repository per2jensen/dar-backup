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
# LC_MESSAGES=C keeps dar's diagnostic output in English so dar-backup can
# parse inode counts reliably.  Your LANG (any *.UTF-8 locale) is inherited
# from the session and controls file-name encoding — leave it unchanged.
Environment=LC_MESSAGES=C
ExecStart=/bin/bash -c 'PATH=$HOME/.local/dar/bin:$PATH && . $HOME/programmer/dar-backup.py/venv/bin/activate && exec dar-backup -I --verbose --log-stdout'
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

## Locale settings

The generated service units set `LC_MESSAGES=C`. This keeps `dar`'s
diagnostic output in English so `dar-backup` can reliably parse inode counts
from the backup summary. It does **not** touch `LANG`.

Your `LANG` (inherited from the user session or the system default) controls
file-name encoding. Any `*.UTF-8` locale works — `en_US.UTF-8`, `de_DE.UTF-8`,
`fr_FR.UTF-8`, and so on. The only requirement is that the encoding is UTF-8;
a non-UTF-8 locale (e.g. bare `C` or `POSIX`) will mangle non-ASCII file names
and `dar-backup-systemd` will warn you at unit-generation time.

If you need to override the locale for the service, edit the `Environment=`
line in the generated `.service` file, e.g.:

```ini
Environment=LC_MESSAGES=C LANG=ja_JP.UTF-8
```

## systemd timer note

OnCalendar syntax is flexible — you can tweak backup schedules easily. Run `systemd-analyze calendar` to preview timers.
