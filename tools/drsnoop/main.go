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
	Task        [16]byte
	DeltaNs     uint64
	NrReclaimed uint64
	NrFreePages uint64
	Pid         uint32
}

func (e Event) TaskString() string {
	return string(bytes.TrimRight(e.Task[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	duration   uint32
	extended   bool
	pid        uint32
	tid        uint32
	verbose    bool
}

var opts = Options{
	bpfObjPath: "drsnoop.bpf.o",
	duration:   0,
	extended:   false,
	pid:        0,
	tid:        0,
	verbose:    false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.duration, "duration", "d", opts.duration, "Total duration of trace in seconds")
	flag.BoolVarP(&opts.extended, "extended", "e", opts.extended, "Extended fields output")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.Uint32VarP(&opts.tid, "tid", "t", opts.tid, "Thread TID to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVariable(bpfModule *bpf.Module, name string, value interface{}) {
	err := bpfModule.InitGlobalVariable(name, value)
	if err != nil {
		log.Fatalf("init global variable %s with value %v failed: %s", name, value, err)
	}
}

func applyArgs(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		initGlobalVariable(bpfModule, "targ_tgid", opts.pid)
	}
	if opts.tid > 0 {
		initGlobalVariable(bpfModule, "targ_pid", opts.tid)
	}
	if opts.extended {
		// TODO:
	}
}

func formatEvent(event Event) {
	ts := time.Now().Format("15:04:05")
	fmt.Printf("%-8s %-16s %-6d %8.3f %5d",
		ts, event.TaskString(), event.Pid, float64(event.DeltaNs)/float64(1000000.0),
		event.NrReclaimed)
	if opts.extended {
		// TODO:
	}
	fmt.Println()
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	applyArgs(bpfModule)
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}

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

	fmt.Printf("Tracing direct reclaim events")
	if opts.duration > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancelFunc()
		fmt.Printf(" for %d secs.\n", opts.duration)
	} else {
		fmt.Print("... Hit Ctrl-C to end.\n")
	}
	fmt.Printf("%-8s %-16s %-6s %8s %5s", "TIME", "COMM", "TID", "LAT(ms)", "PAGES")

loop:
	for {
		select {
		case data := <-eventsChannel:
			var event Event
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
