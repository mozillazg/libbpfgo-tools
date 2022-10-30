# readahead

## build

```
make
```

## run

```
$ sudo ./readahead
Tracing fs read-ahead ... Hit Ctrl-C to end.
^CReadahead unused/total pages: 0/199
     msecs               : count    distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 71       |**********************                  |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 127      |****************************************|
        16 -> 31         : 1        |                                        |
```
