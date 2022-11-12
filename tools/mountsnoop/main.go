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
	MOUNT = iota
	UMOUNT
)

const (
	TASK_COMM_LEN     = 16
	FS_NAME_LEN       = 8
	DATA_LEN          = 512
	PATH_MAX          = 4096
	PERF_BUFFER_PAGES = 64
)

type Event struct {
	Delta uint64
	Flags uint64
	Pid   uint32
	Tid   uint32
	MntNs uint32
	Ret   int32
	Comm  [TASK_COMM_LEN]byte
	Fs    [FS_NAME_LEN]byte
	Src   [PATH_MAX]byte
	Dest  [PATH_MAX]byte
	Data  [DATA_LEN]byte
	Op    int32
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	detailed   bool
	pid        uint32
}

var opts = Options{
	bpfObjPath: "mountsnoop.bpf.o",
	verbose:    false,
	timestamp:  false,
	detailed:   false,
	pid:        0,
}

var flagNames = []string{
	"MS_RDONLY",
	"MS_NOSUID",
	"MS_NODEV",
	"MS_NOEXEC",
	"MS_SYNCHRONOUS",
	"MS_REMOUNT",
	"MS_MANDLOCK",
	"MS_DIRSYNC",
	"MS_NOSYMFOLLOW",
	"MS_NOATIME",
	"MS_NODIRATIME",
	"MS_BIND",
	"MS_MOVE",
	"MS_REC",
	"MS_VERBOSE",
	"MS_SILENT",
	"MS_POSIXACL",
	"MS_UNBINDABLE",
	"MS_PRIVATE",
	"MS_SLAVE",
	"MS_SHARED",
	"MS_RELATIME",
	"MS_KERNMOUNT",
	"MS_I_VERSION",
	"MS_STRICTATIME",
	"MS_LAZYTIME",
	"MS_SUBMOUNT",
	"MS_NOREMOTELOCK",
	"MS_NOSEC",
	"MS_BORN",
	"MS_ACTIVE",
	"MS_NOUSER",
}
var opNames = []string{"MOUNT", "UMOUNT"}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.detailed, "detailed", "d", opts.detailed, "Output result in detail mode")
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
	indent := ""
	if opts.timestamp {
		ts := time.Now().Format("15:04:05")
		fmt.Printf("%8s ", ts)
		indent = "    "
	}
	if !opts.detailed {
		fmt.Printf("%-16s %-7d %-7d %-11d %s\n",
			common.GoString(e.Comm[:]), e.Pid, e.Tid, e.MntNs, genCall(e))
		return
	}
	if opts.timestamp {
		fmt.Printf("\n")
	}
	fmt.Printf("%sPID:    %d\n", indent, e.Pid)
	fmt.Printf("%sTID:    %d\n", indent, e.Tid)
	fmt.Printf("%sCOMM:   %s\n", indent, e.Comm)
	fmt.Printf("%sOP:     %s\n", indent, opNames[e.Op])
	fmt.Printf("%sRET:    %s\n", indent, strErrno(int(e.Ret)))
	fmt.Printf("%sLAT:    %dus\n", indent, e.Delta/1000)
	fmt.Printf("%sMNT_NS: %d\n", indent, e.MntNs)
	fmt.Printf("%sFS:     %s\n", indent, e.Fs)
	fmt.Printf("%sSOURCE: %s\n", indent, e.Src)
	fmt.Printf("%sTARGET: %s\n", indent, e.Dest)
	fmt.Printf("%sDATA:   %s\n", indent, e.Data)
	fmt.Printf("%sFLAGS:  %s\n", indent, strFlags(e.Flags))
	fmt.Printf("\n")
}

func strErrno(errNu int) string {
	ret := common.GetErrName(syscall.Errno(-errNu))
	if ret == "" {
		ret = fmt.Sprintf("%d", errNu)
	} else {
		ret = fmt.Sprintf("-%s", ret)
	}
	return ret
}

func genCall(e Event) string {
	var call string
	if e.Op == UMOUNT {
		call = fmt.Sprintf("umount(\"%s\", %s) = %s",
			common.GoPath(e.Dest[:]), strFlags(e.Flags), strErrno(int(e.Ret)))
	} else {
		call = fmt.Sprintf("mount(\"%s\", \"%s\", \"%s\", %s, \"%s\") = %s",
			common.GoPath(e.Src[:]), common.GoPath(e.Dest[:]),
			common.GoPath(e.Fs[:]), strFlags(e.Flags), common.GoString(e.Data[:]),
			strErrno(int(e.Ret)))
	}
	return call
}

func strFlags(flags uint64) string {
	if flags <= 0 {
		return "0x0"
	}
	var names []string
	for i, name := range flagNames {
		if ((1 << i) & flags) <= 0 {
			continue
		}
		names = append(names, name)
	}
	return strings.Join(names, " | ")
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

	if !opts.detailed {
		if opts.timestamp {
			fmt.Printf("%-8s ", "TIME")
		}
		fmt.Printf("%-16s %-7s %-7s %-11s %s\n", "COMM", "PID", "TID", "MNT_NS", "CALL")
	}

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
