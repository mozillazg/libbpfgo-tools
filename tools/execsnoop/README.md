# execsnoop

## build

```
make
```

## run

```
$ sudo ./execsnoop
PCOMM            PID    PPID   RET ARGS
run              2510030 12772    0 ./run
calico-node      2510030 12772    0 /usr/bin/calico-node -allocate-tunnel-addrs
run              2510039 12770    0 ./run
calico-node      2510039 12770    0 /usr/bin/calico-node -felix
run              2510046 12771    0 ./run
calico-node      2510046 12771    0 /usr/bin/calico-node -monitor-addresses
run              2510052 12773    0 ./run
calico-node      2510052 12773    0 /usr/bin/calico-node -status-reporter
```
