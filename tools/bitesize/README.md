# bitesize

## build

```
make
```

## run

```
$ sudo ./bitesize
Tracing block device I/O... Hit Ctrl-C to end.
^C

Process Name = kworker/0:1H
     Kbytes              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 2        |****************************************|

Process Name = kworker/1:1H
     Kbytes              : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 43       |****************************************|
         8 -> 15         : 5        |****                                    |
```
