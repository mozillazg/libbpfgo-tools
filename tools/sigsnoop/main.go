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
	Pid  uint32
	Tpid uint32
	Sig  uint32
	Ret  int32
	Comm [16]byte
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	failed     bool
	kill       bool
	pid        uint32
	signal     uint32
	name       bool
	verbose    bool
}

var opts = Options{
	bpfObjPath: "sigsnoop.bpf.o",
	failed:     false,
	kill:       false,
	pid:        0,
	signal:     0,
	name:       false,
	verbose:    false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.failed, "failed", "x", opts.failed, "Trace failed signals only")
	flag.BoolVarP(&opts.kill, "kill", "k", opts.kill, "Trace signals issued by kill syscall only")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.Uint32VarP(&opts.signal, "signal", "s", opts.signal, "Signal to trac")
	flag.BoolVarP(&opts.name, "name", "n", opts.name, "Output signal name instead of signal number")
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
		initGlobalVariable(bpfModule, "filtered_pid", opts.pid)
	}
	if opts.failed {
		initGlobalVariable(bpfModule, "failed_only", true)
	}
	if opts.signal > 0 {
		initGlobalVariable(bpfModule, "target_signal", opts.signal)
	}
}

func formatEvent(event Event) {
	if opts.name {
		// sig := event.Sig & 0x7f
		fmt.Printf("%-8s %-7d %-16s %-9s %-7d %-6d\n",
			time.Now().Format("15:04:05"), event.Pid, event.CommString(),
			getSignalName(event.Sig), event.Tpid, event.Ret)
	} else {
		fmt.Printf("%-8s %-7d %-16s %-9d %-7d %-6d\n",
			time.Now().Format("15:04:05"), event.Pid, event.CommString(),
			event.Sig, event.Tpid, event.Ret)
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

	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if opts.kill {
			if prog.Name() == "sig_trace" {
				continue
			}
		} else {
			if prog.Name() != "sig_trace" {
				continue
			}
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

	fmt.Printf("%-8s %-7s %-16s %-9s %-7s %-6s\n",
		"TIME", "PID", "COMM", "SIG", "TPID", "RESULT")

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
