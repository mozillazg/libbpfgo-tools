package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const TASK_COMM_LEN = 16

type BindEvent struct {
	Addr       common.Uint128
	TsUs       uint64
	Pid        uint32
	BoundDevIf uint32
	Ret        uint32
	Port       uint16
	Proto      uint16
	Opts       uint8
	Ver        uint8
	Task       [TASK_COMM_LEN]byte
}

type Options struct {
	bpfObjPath string
	timestamp  bool
	cgroup     string
	failed     bool
	pid        uint
	ports      []uint
	verbose    bool
}

var opts = Options{
	bpfObjPath: "bindsnoop.bpf.o",
	timestamp:  false,
	cgroup:     "",
	failed:     false,
	pid:        0,
	ports:      nil,
	verbose:    false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
	flag.BoolVarP(&opts.failed, "failed", "x", opts.failed, "Include errors on output")
	flag.UintVarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.UintSliceVarP(&opts.ports, "ports", "P", opts.ports, "Comma-separated list of ports to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func checkArgs() {
	for _, p := range opts.ports {
		if p > 65536 {
			log.Fatalf("Invalid ports: %v", opts.ports)
		}
	}
}

func initGlobalVariable(bpfModule *bpf.Module, name string, value interface{}) {
	err := bpfModule.InitGlobalVariable(name, value)
	if err != nil {
		log.Fatalf("init global variable %s with value %v failed: %s", name, value, err)
	}
}

func initFilters(bpfModule *bpf.Module) {
	if opts.cgroup != "" {
		idx := 0
		cgroupFd, err := common.GetCgroupDirFD(opts.cgroup)
		if err != nil {
			log.Fatalln(err)
		}
		cgroupMap, err := bpfModule.GetMap("cgroup_map")
		if err != nil {
			log.Fatalln(err)
		}
		if err := cgroupMap.Update(unsafe.Pointer(&idx), unsafe.Pointer(&cgroupFd)); err != nil {
			log.Fatalln(err)
		}
	}
	if len(opts.ports) > 0 {
		portsMap, err := bpfModule.GetMap("ports")
		if err != nil {
			log.Fatalln(err)
		}
		for _, p := range opts.ports {
			k := p
			if err := portsMap.Update(unsafe.Pointer(&k), unsafe.Pointer(&k)); err != nil {
				log.Fatalln(err)
			}
		}
	}
}

func formatEvent(event BindEvent) {
	var proto string
	var addr string
	bindOpts := []byte{'F', 'T', 'N', 'R', 'r'}
	if opts.timestamp {
		fmt.Printf("%8s ", time.Now().Format("15:04:05"))
	}
	switch event.Proto {
	case common.IPPROTO_TCP:
		proto = "TCP"
		break
	case common.IPPROTO_UDP:
		proto = "UDP"
	default:
		proto = "UNK"
	}
	for i, _ := range bindOpts {
		if ((1 << i) & event.Opts) == 0 {
			bindOpts[i] = '.'
		}
	}
	switch event.Ver {
	case 4:
		addr = common.AddrFrom16(common.AF_INET, event.Addr).String()
	default:
		addr = common.AddrFrom16(common.AF_INET6, event.Addr).String()
	}
	fmt.Printf("%-7d %-16s %-3d %-5s %-5s %-4d %-5d %-48s\n",
		event.Pid, common.GoString(event.Task[:]), event.Ret, proto, bindOpts, event.BoundDevIf, event.Port, addr)
}

func main() {
	flag.Parse()
	checkArgs()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVariable(bpfModule, "target_pid", uint32(opts.pid))
	initGlobalVariable(bpfModule, "ignore_errors", !opts.failed)
	initGlobalVariable(bpfModule, "filter_by_port", len(opts.ports) > 0)
	initGlobalVariable(bpfModule, "filter_cg", opts.cgroup != "")
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	initFilters(bpfModule)

	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		_, err := prog.AttachGeneric()
		if err != nil {
			log.Fatalln(err)
		}
	}

	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		log.Fatalln(err)
	}

	pb.Start()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		pb.Stop()
		pb.Close()
		stop()
	}()

	if opts.timestamp {
		fmt.Printf("%-8s ", "TIME(s)")
	}
	fmt.Printf("%-7s %-16s %-3s %-5s %-5s %-4s %-5s %-48s\n",
		"PID", "COMM", "RET", "PROTO", "OPTS", "IF", "PORT", "ADDR")

loop:
	for {
		select {
		case data := <-eventsChannel:
			var event BindEvent
			err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("read data failed: %s\n%v", err, data)
			}
			formatEvent(event)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
