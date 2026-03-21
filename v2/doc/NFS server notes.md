#NFS server notes

find /samba/dar \
    -type f \
    -mmin +2880 \
    ! -user root \
    -exec chown root:root {} + \
    -exec chmod 0444 {} +
usermod -aG backup pj

chown root:backup /samba/dar
chmod 1770 /samba/dar

chown root:backup /mnt/par2
chmod 1770 /mnt/par2

chmod g+s /samba/dar
chmod g+s /mnt/par2/

## /etc/systemd/system/lock-old-archives.service
[Unit]
Description=Lock old DAR archives (make read-only and root owned)
Documentation=man:find(1)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/lock-old-archives.sh

# Hardening (safe for this script)
User=root
Group=root
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/samba/dar /mnt/par2

## /etc/systemd/system/lock-old-archives.timer
[Unit]
Description=Run archive locking nightly at 21:17

[Timer]
OnCalendar=*-*-* 21:17:00
Persistent=true
AccuracySec=1min

[Install]
WantedBy=timers.target
