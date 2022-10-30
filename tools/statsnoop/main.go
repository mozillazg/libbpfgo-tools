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
	flag "github.com/spf13/pflag"
)

type Event struct {
	TsNs     uint64
	Pid      uint32
	Ret      int32
	Comm     [16]byte
	Pathname [255]byte
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

func (e Event) PathnameString() string {
	return string(bytes.TrimRight(e.Pathname[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	pid        uint32
	failed     bool
}

var opts = Options{
	bpfObjPath: "statsnoop.bpf.o",
	verbose:    false,
	timestamp:  false,
	pid:        0,
	failed:     false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.BoolVarP(&opts.failed, "failed", "x", opts.failed, "Only show failed stats")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
}

func printEvent(data []byte) {
	var e Event
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}

	var fd, err int
	if e.Ret >= 0 {
		fd = int(e.Ret)
		err = 0
	} else {
		fd = -1
		err = -int(e.Ret)
	}
	startTimestamp := e.TsNs
	if opts.timestamp {
		ts := float64(e.TsNs-startTimestamp) / 1000000000
		fmt.Printf("%-14.9f ", ts)
	}
	fmt.Printf("%-7d %-20s %-4d %-4d %-s\n", e.Pid, e.CommString(), fd, err, e.PathnameString())
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("target_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.failed {
		if err := bpfModule.InitGlobalVariable("trace_failed_only", true); err != nil {
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

func main() {
	parseArgs()

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

	if opts.timestamp {
		fmt.Printf("%-14s ", "TIME(s)")
	}
	fmt.Printf("%-7s %-20s %-4s %-4s %-s\n", "PID", "COMM", "RET", "ERR", "PATH")

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
