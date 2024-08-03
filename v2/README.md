
# .conf file

The default configuration is located here: ~/.config/dar-backup/dar-backup.conf

# How to run 

Installation is in a venv. These commands are installed in the venv:
- dar-back
- cleanup


./backup_script.py --config-dir /path/to/configs

With a single config snippet
python3 src/backup_script.py  --config-file backup.d/example


# list contents of an archive
```
. <the virtual evn>/bin/activate
dar-backup --list-contents example --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```




# dar file selection exmaples

## select a directory
```
dar -l /tmp/example_FULL_2024-06-23  -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	48 kio	Sat Jun 22 21:51:24 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	50 kio	Sat Jun 22 21:51:25 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:26 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj	pj	77 kio	Sat Jun 22 21:50:16 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	52 kio	Sat Jun 22 21:49:37 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:47 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:39 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:36 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:35 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj	pj	15 kio	Sat Jun 22 21:51:11 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	84 kio	Sat Jun 22 21:51:09 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	90 kio	Sat Jun 22 21:51:04 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:15 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:48 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:19 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
```


## select file dates in the directory:
```
dar -l /tmp/example_FULL_2024-06-23  -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	48 kio	Sat Jun 22 21:51:24 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	50 kio	Sat Jun 22 21:51:25 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_01.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:26 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_02.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_03.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	51 kio	Sat Jun 22 21:51:27 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_04.NEF.xmp
[Saved][ ]       [-L-][  97%][ ]  -rw-rw-r--   pj	pj	77 kio	Sat Jun 22 21:50:16 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_05.NEF.xmp
[Saved][ ]       [-L-][  95%][ ]  -rw-rw-r--   pj	pj	52 kio	Sat Jun 22 21:49:37 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_06.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:47 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_07.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_08.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:12 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_09.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:39 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_10.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:36 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_11.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:35 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_12.NEF.xmp
[Saved][ ]       [-L-][  88%][ ]  -rw-rw-r--   pj	pj	15 kio	Sat Jun 22 21:51:11 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_13.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	84 kio	Sat Jun 22 21:51:09 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_14.NEF.xmp
[Saved][ ]       [-L-][  96%][ ]  -rw-rw-r--   pj	pj	90 kio	Sat Jun 22 21:51:04 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_15.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:51:15 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_16.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:48 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_17.NEF.xmp
[Saved][ ]       [-L-][  92%][ ]  -rw-rw-r--   pj	pj	24 kio	Sat Jun 22 21:50:19 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15_18.NEF.xmp
```

## exclude .xmp files from that date
```
dar -l /tmp/example_FULL_2024-06-23 -X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play
```
gives
```
[Data ][D][ EA  ][FSA][Compr][S]| Permission | User  | Group | Size    |          Date                 |    filename
--------------------------------+------------+-------+-------+---------+-------------------------------+------------
[Saved][-]       [-L-][   0%][ ]  drwxr-xr-x   root	root	113 Mio	Sat May 11 16:16:48 2024	home
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 10:46:30 2024	home/pj
[Saved][-]       [-L-][   0%][ ]  drwxrwxr-x   pj	pj	113 Mio	Sun Jun 23 09:17:42 2024	home/pj/tmp
[Saved][-]       [-L-][   1%][ ]  drwxrwxr-x   pj	pj	50 Mio	Wed Jun 19 20:52:13 2024	home/pj/tmp/LUT-play
[Saved][ ]       [-L-][   0%][X]  -rw-rw-r--   pj	pj	49 Mio	Sun Jun 16 12:52:22 2024	home/pj/tmp/LUT-play/2024-06-16_12:52:22,15.NEF
```

Nice :-)



# Restoring

## a single file
```
. <the virtual evn>/bin/activate
# the path/to/file is relative to the Root when the backup was taken
dar-backup --restore <archive_name> --selection "-g path/to/file"
deactivate
```

## .NEF from a specific date
```
. <the virtual evn>/bin/activate
# the path/to/file is relative to the Root when the backup was taken
dar-backup --restore <archive_name>  --selection "-X '*.xmp' -I '*2024-06-16*' -g home/pj/tmp/LUT-play"
deactivate
```



