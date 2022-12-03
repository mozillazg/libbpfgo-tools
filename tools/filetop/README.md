# filetop

## build

```
make
```

## run

```
$ sudo ./filetop
14:25:19 loadavg: 0.02 0.01 0.00 2/170 31902
TID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
31902   clear            2      0      60      0       R xterm-256color
31902   clear            5      0      2       0       R libc.so.6
31896   filetop          2      0      0       0       R loadavg
31902   clear            1      0      0       0       R libtinfo.so.6.3

$ sudo ./filetop  -C -r 5 -s reads
15:06:13 loadavg: 0.14 0.33 0.27 4/180 181017
TID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
181011  filetop          4      0      16      0       R type
363     systemd-journal  3      0      6       0       R status
363     systemd-journal  2      0      2       0       R comm
363     systemd-journal  2      0      2       0       R loginuid
181017  sleep            2      0      8       0       R locale.alias
```
