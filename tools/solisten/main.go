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
	TASK_COMM_LEN = 16
)

type Event struct {
	Addr    common.Uint128
	Pid     uint32
	Proto   uint32
	Backlog uint32
	Ret     int32
	Port    uint16
	Task    [TASK_COMM_LEN]byte
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	pid        uint32
}

var opts = Options{
	bpfObjPath: "solisten.bpf.o",
	verbose:    false,
	timestamp:  false,
	pid:        0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process PID to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("target_pid", opts.pid); err != nil {
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
	progNames := []string{"inet_listen_fexit"}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if !common.Contains(progNames, prog.Name()) {
			continue
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
		ts := time.Now().Format("15:04:05")
		fmt.Printf("%8s ", ts)
	}

	family := e.Proto >> 16
	_type := uint16(e.Proto)
	prot := "UNK"
	if _type == common.SOCK_STREAM {
		prot = "TCP"
	} else if _type == common.SOCK_DGRAM {
		prot = "UDP"
	}
	suffix := "v4"
	if family == common.AF_INET6 {
		suffix = "v6"
	}
	addr := common.AddrFrom16(uint16(family), e.Addr).String()
	proto := fmt.Sprintf("%s%s", prot, suffix)
	fmt.Printf("%-7d %-16s %-3d %-7d %-5s %-5d %-32s\n",
		e.Pid, common.GoString(e.Task[:]), e.Ret, e.Backlog, proto, e.Port, addr)
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
		fmt.Printf("%-8s ", "TIME(s)")
	}
	fmt.Printf("%-7s %-16s %-3s %-7s %-5s %-5s %-32s\n",
		"PID", "COMM", "RET", "BACKLOG", "PROTO", "PORT", "ADDR")

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
