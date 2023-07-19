# libbpfgo-tools

[![Build tools](https://github.com/mozillazg/libbpfgo-tools/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/mozillazg/libbpfgo-tools/actions/workflows/build.yml)

[libbpfgo](https://github.com/aquasecurity/libbpfgo) port of [bcc/libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools).


## tools (30/52)

* [x] [bashreadline](./tools/bashreadline)
* [x] [bindsnoop](./tools/bindsnoop)
* [x] [biolatency](./tools/biolatency)
* [x] [biopattern](./tools/biopattern)
* [x] [biosnoop](./tools/biosnoop), This command can not working on kernel which the version is greater than 5.17, see [iovisor/bcc#4261](https://github.com/iovisor/bcc/issues/4261) for details.
* [x] [biostacks](./tools/biostacks)
* ~~[ ] biotop~~ This command would not be implemented, see [iovisor/bcc#4261](https://github.com/iovisor/bcc/issues/4261) for details.
* [x] [bitesize](./tools/bitesize)
* [ ] cachestat
* [ ] capable
* [x] [cpudist](./tools/cpudist)
* [ ] cpufreq
* [x] [drsnoop](./tools/drsnoop)
* [x] [execsnoop](./tools/execsnoop)
* [x] [exitsnoop](./tools/exitsnoop)
* [x] [filelife](./tools/filelife)
* [x] [filetop](./tools/filetop)
* [x] [fsdist](./tools/fsdist)
* [x] [fsslower](./tools/fsslower)
* [ ] funclatency
* [ ] gethostlatency
* [ ] hardirqs
* [ ] javagc
* [ ] klockstat
* [ ] ksnoop
* [ ] llcstat
* [x] [mdflush](./tools/mdflush)
* [x] [mountsnoop](./tools/mountsnoop)
* [ ] numamove
* [ ] offcputime
* [x] [oomkill](./tools/oomkill)
* [x] [opensnoop](./tools/opensnoop)
* [x] [readahead](./tools/readahead)
* [ ] runqlat
* [ ] runqlen
* [ ] runqslower
* [x] [sigsnoop](./tools/sigsnoop)
* [ ] slabratetop
* [ ] softirqs
* [x] [solisten](./tools/solisten)
* [x] [statsnoop](./tools/statsnoop)
* [x] [syscount](./tools/syscount)
* [x] [tcpconnect](./tools/tcpconnect)
* [x] [tcpconnlat](./tools/tcpconnlat)
* [x] [tcplife](./tools/tcplife)
* [x] [tcprtt](./tools/tcprtt)
* [ ] tcpstates
* [x] [tcpsynbl](./tools/tcpsynbl)
* [ ] tcptop
* [x] [tcptracer](./tools/tcptracer)
* [ ] vfsstat
* [x] [wakeuptime](./tools/wakeuptime)
