# fsdist

## build

```
make
```

## run

```
$ sudo ./fsdist -t ext4
Tracing ext4 operation latency... Hit Ctrl-C to end.
^C
operation = 'read'
     usecs               : count    distribution
         0 -> 1          : 1        |****************************************|
         2 -> 3          : 1        |****************************************|

operation = 'open'
     usecs               : count    distribution
         0 -> 1          : 14       |****************************************|
         2 -> 3          : 1        |**                                      |

operation = 'getattr'
     usecs               : count    distribution
         0 -> 1          : 15       |****************************************|
         2 -> 3          : 2        |*****                                   |


$ sudo ./fsdist -t ext4 10 1
Tracing ext4 operation latency... Hit Ctrl-C to end.

operation = 'read'
     usecs               : count    distribution
         0 -> 1          : 52       |****************************************|
         2 -> 3          : 13       |**********                              |
         4 -> 7          : 3        |**                                      |
         8 -> 15         : 1        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 0        |                                        |
        64 -> 127        : 1        |                                        |

operation = 'write'
     usecs               : count    distribution
         0 -> 1          : 24       |****************************************|
         2 -> 3          : 4        |******                                  |
         4 -> 7          : 5        |********                                |
         8 -> 15         : 9        |***************                         |
        16 -> 31         : 5        |********                                |
        32 -> 63         : 2        |***                                     |

operation = 'open'
     usecs               : count    distribution
         0 -> 1          : 96       |****************************************|
         2 -> 3          : 14       |*****                                   |
         4 -> 7          : 4        |*                                       |

operation = 'getattr'
     usecs               : count    distribution
         0 -> 1          : 106      |****************************************|
         2 -> 3          : 9        |***                                     |
         4 -> 7          : 2        |                                        |
         8 -> 15         : 1        |                                        |
```
