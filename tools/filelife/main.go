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
	flag "github.com/spf13/pflag"
)

type Event struct {
	File    [32]byte
	Task    [16]byte
	DeltaNs uint64
	Tgid    uint32
}

func (e Event) FileString() string {
	return string(bytes.TrimRight(e.File[:], "\x00"))
}

func (e Event) TaskString() string {
	return string(bytes.TrimRight(e.Task[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	verbose    bool
	pid        uint32
}

var opts = Options{
	bpfObjPath: "filelife.bpf.o",
	verbose:    false,
	pid:        0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process PID to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_tgid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
}

func attachPrograms(bpfModule *bpf.Module) {
	// TODO: kprobe_exists("security_inode_create")
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

	ts := time.Now().Format("15:04:05")
	fmt.Printf("%-8s %-6d %-16s %-7.2f %s\n",
		ts, e.Tgid, e.TaskString(), float64(e.DeltaNs/1000000000.0),
		e.FileString())
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	initGlobalVars(bpfModule)
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

	fmt.Printf("Tracing the lifespan of short-lived files ... Hit Ctrl-C to end.\n")
	fmt.Printf("%-8s %-6s %-16s %-7s %s\n", "TIME", "PID", "COMM", "AGE(s)", "FILE")

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
