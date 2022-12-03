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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	TASK_COMM_LEN = 16
)

const (
	TCP_EVENT_TYPE_CONNECT = iota
	TCP_EVENT_TYPE_ACCEPT
	TCP_EVENT_TYPE_CLOSE
)

var startTs uint64

type Event struct {
	Saddr common.Uint128
	Daddr common.Uint128
	Task  [TASK_COMM_LEN]byte
	TsUs  uint64
	Af    uint32
	Pid   uint32
	Uid   uint32
	Netns uint32
	Dport uint16
	Sport uint16
	Type  uint8
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	printUid   bool
	pid        uint32
	uid        uint32
	cgroupmap  string
	mntnsmap   string
}

var opts = Options{
	bpfObjPath: "tcptracer.bpf.o",
	verbose:    false,
	timestamp:  false,
	printUid:   false,
	pid:        0,
	uid:        0,
	cgroupmap:  "",
	mntnsmap:   "",
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.printUid, "print-uid", "U", opts.printUid, "Include UID on output")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process PID to trace")
	flag.Uint32VarP(&opts.uid, "uid", "u", opts.uid, "Process UID to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("filter_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.uid > 0 {
		if err := bpfModule.InitGlobalVariable("filter_uid", opts.uid); err != nil {
			log.Fatalln(err)
		}
	}
}

func loadBPFObj(bpfModule *bpf.Module) {
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
}

func applyFilters(bpfModule *bpf.Module) {
}

func attachPrograms(bpfModule *bpf.Module) {
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
}

func printEvent(data []byte) {
	var e Event
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)
	if err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}
	if opts.timestamp {
		if startTs == 0 {
			startTs = e.TsUs
		}
		fmt.Printf("%-9.3f", float64(e.TsUs-startTs)/1000000.0)
	}
	if opts.printUid {
		fmt.Printf("%-6d", e.Uid)
	}

	af := 4
	if e.Af == common.AF_INET6 {
		af = 6
	}
	_type := '-'
	switch e.Type {
	case TCP_EVENT_TYPE_CONNECT:
		_type = 'C'
		break
	case TCP_EVENT_TYPE_ACCEPT:
		_type = 'A'
		break
	case TCP_EVENT_TYPE_CLOSE:
		_type = 'X'
		break
	}

	fmt.Printf("%c %-6d %-12.12s %-2d %-16s %-16s %-4d %-4d\n",
		_type, e.Pid, common.GoString(e.Task[:]), af,
		common.AddrFrom16(uint16(e.Af), e.Saddr).String(),
		common.AddrFrom16(uint16(e.Af), e.Daddr).String(),
		common.Ntohs(e.Sport), common.Ntohs(e.Dport))
}

func main() {
	parseArgs()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule)
	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
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

	if opts.timestamp {
		fmt.Printf("%-9s", "TIME(s)")
	}
	if opts.printUid {
		fmt.Printf("%-6s", "UID")
	}
	fmt.Printf("%s %-6s %-12s %-2s %-16s %-16s %-4s %-4s\n",
		"T", "PID", "COMM", "IP", "SADDR", "DADDR", "SPORT", "DPORT")

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
