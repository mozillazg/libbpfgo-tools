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
	flag "github.com/spf13/pflag"
)

var signalNameMap = map[syscall.Signal]string{
	syscall.SIGABRT: "SIGABRT",
	syscall.SIGALRM: "SIGALRM",
	syscall.SIGCHLD: "SIGCHLD",
	syscall.SIGCONT: "SIGCONT",
	// syscall.SIGEMT:  "SIGEMT",
	syscall.SIGFPE: "SIGFPE",
	syscall.SIGHUP: "SIGHUP",
	syscall.SIGILL: "SIGILL",
	syscall.SIGINT: "SIGINT",
	syscall.SIGIO:  "SIGIO",
	// syscall.SIGIOT:  "SIGIOT",
	syscall.SIGKILL: "SIGKILL",
	syscall.SIGPIPE: "SIGPIPE",
	// syscall.SIGPOLL:   "SIGPOLL",
	syscall.SIGPROF:   "SIGPROF",
	syscall.SIGPWR:    "SIGPWR",
	syscall.SIGQUIT:   "SIGQUIT",
	syscall.SIGSEGV:   "SIGSEGV",
	syscall.SIGSTKFLT: "SIGSTKFLT",
	syscall.SIGSTOP:   "SIGSTOP",
	syscall.SIGSYS:    "SIGSYS",
	syscall.SIGTRAP:   "SIGTRAP",
	syscall.SIGTSTP:   "SIGTSTP",
	syscall.SIGTTIN:   "SIGTTIN",
	syscall.SIGTTOU:   "SIGTTOU",
	// syscall.SIGUNUSED: "SIGUNUSED",
	syscall.SIGURG:    "SIGURG",
	syscall.SIGUSR1:   "SIGUSR1",
	syscall.SIGUSR2:   "SIGUSR2",
	syscall.SIGVTALRM: "SIGVTALRM",
	syscall.SIGWINCH:  "SIGWINCH",
	syscall.SIGXCPU:   "SIGXCPU",
	syscall.SIGXFSZ:   "SIGXFSZ",
}

type Event struct {
	StartTime uint64
	ExitTime  uint64
	Pid       uint32
	Tid       uint32
	Ppid      uint32
	Sig       uint32
	ExitCode  int32
	Comm      [16]byte
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	timestamp  bool
	failed     bool
	pid        uint
	threaded   bool
	cgroup     string
}

var opts = Options{
	bpfObjPath: "exitsnoop.bpf.o",
	timestamp:  false,
	failed:     false,
	pid:        0,
	threaded:   false,
	cgroup:     "",
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "include timestamp on output")
	flag.BoolVarP(&opts.failed, "failed", "x", opts.failed, "Trace error exits only")
	flag.UintVarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.BoolVarP(&opts.threaded, "threaded", "T", opts.threaded, "Trace by thread")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func getSignalName(signal uint32) string {
	v := signalNameMap[syscall.Signal(signal)]
	if v == "" {
		v = "N/A"
	}
	return v
}

func initGlobalVariable(bpfModule *bpf.Module, name string, value interface{}) {
	err := bpfModule.InitGlobalVariable(name, value)
	if err != nil {
		log.Fatalf("init global variable %s with value %v failed: %s", name, value, err)
	}
}

func initGlobalVariables(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		initGlobalVariable(bpfModule, "target_pid", uint32(opts.pid))
	}
	if opts.failed {
		initGlobalVariable(bpfModule, "trace_failed_only", true)
	}
	if opts.threaded {
		initGlobalVariable(bpfModule, "trace_by_process", false)
	}
	if opts.cgroup != "" {
		initGlobalVariable(bpfModule, "filter_cg", true)
	}
}

func getCgroupDirFD(cgroupV2DirPath string) (int, error) {
	const (
		O_DIRECTORY int = 0200000
		O_RDONLY    int = 00
	)
	fd, err := syscall.Open(cgroupV2DirPath, O_DIRECTORY|O_RDONLY, 0)
	if fd < 0 {
		return 0, fmt.Errorf("failed to open cgroupv2 directory path %s: %w", cgroupV2DirPath, err)
	}
	return fd, nil
}

func initFilters(bpfModule *bpf.Module) {
	if opts.cgroup != "" {
		idx := 0
		cgroupFd, err := getCgroupDirFD(opts.cgroup)
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
}

func formatEvent(event Event) {
	if opts.timestamp {
		fmt.Printf("%8s ", time.Now().Format("15:04:05"))
	}
	age := float64(event.ExitTime-event.StartTime) / 1e9
	fmt.Printf("%-16s %-7d %-7d %-7d %-7.2f ",
		event.CommString(), event.Pid, event.Ppid, event.Tid, age)
	if event.Sig == 0 {
		if event.ExitCode <= 0 {
			fmt.Printf("0\n")
		} else {
			fmt.Printf("code %d\n", event.ExitCode)
		}
	} else {
		sig := event.Sig & 0x7f
		coredump := event.Sig & 0x80
		if sig > 0 {
			fmt.Printf("signal %d (%s)", sig, getSignalName(sig))
		}
		if coredump > 0 {
			fmt.Printf(", core dumped")
		}
		fmt.Printf("\n")
	}
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVariables(bpfModule)
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
	fmt.Printf("%-16s %-7s %-7s %-7s %-7s %-s\n",
		"PCOMM", "PID", "PPID", "TID", "AGE(s)", "EXIT_CODE")

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
