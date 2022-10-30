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
	Pid  uint32
	Comm [16]byte
	Disk [32]byte
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

func (e Event) DiskString() string {
	return string(bytes.TrimRight(e.Disk[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	verbose    bool
	pid        uint32
}

var opts = Options{
	bpfObjPath: "mdflush.bpf.o",
	verbose:    false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	//
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

	ts := time.Now().Format("15:04:05")
	fmt.Printf("%-8s %-7d %-16s %-s\n",
		ts, e.Pid, e.CommString(), e.DiskString())
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

	fmt.Printf("Tracing md flush requests... Hit Ctrl-C to end.\n")
	fmt.Printf("%-8s %-7s %-16s %-s\n", "TIME", "PID", "COMM", "DEVICE")

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
