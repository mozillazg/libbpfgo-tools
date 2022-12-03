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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	AF_INET  = 2
	AF_INET6 = 10
)

var columnWidth = 15

type uint128 [16]byte

type Event struct {
	Saddr  uint128
	Daddr  uint128
	TsUs   uint64
	SpanUs uint64
	RxB    uint64
	TxB    uint64
	Pid    uint32
	Sport  uint16
	Dport  uint16
	Family uint16
	Comm   [16]byte
}

type Options struct {
	bpfObjPath string
	verbose    bool
	pid        uint32
	ipv4       bool
	ipv6       bool
	wide       bool
	time       bool
	localport  []uint
	remoteport []uint
}

var opts = Options{
	bpfObjPath: "tcplife.bpf.o",
	verbose:    false,
	pid:        0,
	ipv4:       false,
	ipv6:       false,
	wide:       false,
	time:       false,
	localport:  nil,
	remoteport: nil,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.BoolVarP(&opts.ipv4, "ipv4", "4", opts.ipv4, "Trace IPv4 only")
	flag.BoolVarP(&opts.ipv6, "ipv6", "6", opts.ipv6, "Trace IPv6 only")
	flag.BoolVarP(&opts.wide, "wide", "w", opts.wide, "Wide column output (fits IPv6 addresses)")
	flag.BoolVarP(&opts.time, "time", "T", opts.time, "Include timestamp on output")
	flag.UintSliceVarP(&opts.localport, "localport", "L", opts.localport, "Comma-separated list of local ports to trace")
	flag.UintSliceVarP(&opts.remoteport, "remoteport", "D", opts.remoteport, "Comma-separated list of remote ports to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.wide {
		columnWidth = 26
	}
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("target_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	var targetFamily uint16
	if opts.ipv4 {
		targetFamily = AF_INET
	}
	if opts.ipv6 {
		targetFamily = AF_INET6
	}
	if targetFamily > 0 {
		if err := bpfModule.InitGlobalVariable("target_family", targetFamily); err != nil {
			log.Fatalln(err)
		}
	}
	if len(opts.localport) > 0 {
		var ports []uint16
		for _, v := range opts.localport {
			ports = append(ports, uint16(v))
		}
		if err := bpfModule.InitGlobalVariable("target_sports", ports); err != nil {
			log.Fatalln(err)
		}
		if err := bpfModule.InitGlobalVariable("filter_sport", true); err != nil {
			log.Fatalln(err)
		}
	}
	if len(opts.remoteport) > 0 {
		var ports []uint16
		for _, v := range opts.remoteport {
			ports = append(ports, uint16(v))
		}
		if err := bpfModule.InitGlobalVariable("target_dports", ports); err != nil {
			log.Fatalln(err)
		}
		if err := bpfModule.InitGlobalVariable("filter_dport", true); err != nil {
			log.Fatalln(err)
		}
	}
}

func attachPrograms(bpfModule *bpf.Module) {
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if _, err := prog.AttachGeneric(); err != nil {
			log.Fatalln(err)
		}
	}
}

func printEvent(data []byte) {
	var e Event
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)
	if err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}

	if opts.time {
		ts := time.Now().Format("15:04:05")
		fmt.Printf("%8s ", ts)
	}
	fmt.Printf("%-7d %-16s %-*s %-5d %-*s %-5d %-6.2f %-6.2f %-.2f\n",
		e.Pid, common.GoString(e.Comm[:]), columnWidth, common.AddrFrom16(e.Family, e.Saddr).String(),
		e.Sport, columnWidth, common.AddrFrom16(e.Family, e.Daddr).String(), e.Dport,
		float64(e.TxB)/1024, float64(e.RxB)/1024, float64(e.SpanUs)/1000)
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule)
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	attachPrograms(bpfModule)

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

	if opts.time {
		fmt.Printf("%-8s ", "TIME(s)")
	}
	fmt.Printf("%-7s %-16s %-*s %-5s %-*s %-5s %-6s %-6s %-s\n",
		"PID", "COMM", columnWidth, "LADDR", "LPORT", columnWidth, "RADDR", "RPORT",
		"TX_KB", "RX_KB", "MS")

loop:
	for {
		select {
		case data := <-eventsChannel:
			printEvent(data)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
