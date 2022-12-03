package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	TASK_COMM_LEN     = 16
	NAME_MAX          = 255
	PERF_BUFFER_PAGES = 64
)

type Event struct {
	Ts    uint64
	Pid   uint32
	Uid   uint32
	Ret   int32
	Flags int32
	Comm  [TASK_COMM_LEN]byte
	Fname [NAME_MAX]byte
}

type Options struct {
	bpfObjPath     string
	verbose        bool
	duration       uint64
	extendedFields bool
	name           string
	pid            uint32
	tid            uint32
	timestamp      bool
	uid            int32
	printUid       bool
	failed         bool
}

var opts = Options{
	bpfObjPath:     "opensnoop.bpf.o",
	verbose:        false,
	duration:       0,
	extendedFields: false,
	name:           "",
	pid:            0,
	tid:            0,
	timestamp:      false,
	uid:            -1,
	printUid:       false,
	failed:         false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint64VarP(&opts.duration, "duration", "d", opts.duration, "Duration to trace")
	flag.BoolVarP(&opts.extendedFields, "extended-fields", "e", opts.extendedFields, "Print extended fields")
	flag.StringVarP(&opts.name, "name", "n", opts.name, "Trace process names containing this")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.Uint32VarP(&opts.tid, "tid", "t", opts.tid, "Thread ID to trace")
	flag.Int32VarP(&opts.uid, "uid", "u", opts.uid, "User ID to trace")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Print timestamp")
	flag.BoolVarP(&opts.printUid, "print-uid", "U", opts.printUid, "Print UID")
	flag.BoolVarP(&opts.failed, "failed", "x", opts.failed, "Failed opens only")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_tgid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.tid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_pid", opts.tid); err != nil {
			log.Fatalln(err)
		}
	}
	if err := bpfModule.InitGlobalVariable("targ_uid", opts.uid); err != nil {
		log.Fatalln(err)
	}
	if opts.failed {
		if err := bpfModule.InitGlobalVariable("targ_failed", true); err != nil {
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
	if opts.name != "" && !strings.Contains(common.GoString(e.Comm[:]), opts.name) {
		return
	}

	ts := time.Now().Format("15:04:05")
	fd := -1
	errR := -e.Ret
	if e.Ret >= 0 {
		fd = int(e.Ret)
		errR = 0
	}

	if opts.timestamp {
		fmt.Printf("%-8s ", ts)
	}
	if opts.printUid {
		fmt.Printf("%-6d ", e.Uid)
	}
	fmt.Printf("%-6d %-16s %3d %3d ", e.Pid, common.GoString(e.Comm[:]), fd, errR)
	if opts.extendedFields {
		fmt.Printf("%08o ", e.Flags)
	}
	fmt.Printf("%s\n", common.GoPath(e.Fname[:]))

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
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, PERF_BUFFER_PAGES)
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
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancel()
	}

	if opts.timestamp {
		fmt.Printf("%-8s ", "TIME")
	}
	if opts.printUid {
		fmt.Printf("%-6s ", "UID")
	}
	fmt.Printf("%-6s %-16s %3s %3s ", "PID", "COMM", "FD", "ERR")
	if opts.extendedFields {
		fmt.Printf("%-8s ", "FLAGS")
	}
	fmt.Printf("%s\n", "PATH")
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
