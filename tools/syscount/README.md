# syscount

## build

```
make
```

## run

```
$ sudo ./syscount
Tracing syscalls, printing top 10... Ctrl+C to quit.
^C[13:51:08]
SYSCALL                   COUNT
futex                        85
epoll_pwait                  50
write                        21
nanosleep                    21
rt_sigprocmask               20
bpf                          16
read                         12
rt_sigaction                 12
ppoll                        11
clock_nanosleep               4
```

```
$ sudo ./syscount -P -d 5 -T 5
Tracing syscalls, printing top 5... Ctrl+C to quit.
[13:53:11]
PID    COMM               COUNT
731    containerd           164
2839   syscount              64
397    multipathd            30
2837   sudo                  10
1747   sshd                   9
```
