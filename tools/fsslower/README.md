# fsslower

## build

```
make
```

## run

```
$ sudo ./fsslower -t ext4 -m 1
Tracing ext4 operations slower than 1 ms... Hit Ctrl-C to end.
TIME     COMM             PID     T BYTES   OFF_KB   LAT(ms) FILENAME
14:19:44 dockerd          170997  F LL_MAX  0           6.85 local-kv.db
^C

$ sudo ./fsslower -t ext4 -d 10 -m 1
Tracing ext4 operations slower than 1 ms for 10 secs.
TIME     COMM             PID     T BYTES   OFF_KB   LAT(ms) FILENAME
14:20:32 grep             171251  O 0       0           1.37 SYS_LC_MESSAGES

$ sudo ./fsslower -t ext4 -p 171259 -m 0
Tracing ext4 operations... Hit Ctrl-C to end.
TIME     COMM             PID     T BYTES   OFF_KB   LAT(ms) FILENAME
14:21:38 dockerd          171259  O 0       0           0.00 os-release
14:21:38 dockerd          171259  R 386     0           0.00 os-release
14:21:38 dockerd          171259  R 0       0           0.00 os-release
14:21:38 dockerd          171259  O 0       0           0.00 os-release
```
