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
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	flag "github.com/spf13/pflag"
)

const (
	TotalMaxArgs = 60
)

type BaseEvent struct {
	Pid       uint32
	Ppid      uint32
	Uid       uint32
	Retval    uint32
	ArgsCount uint32
	ArgsSize  uint32
	Comm      [16]byte
}

type Event struct {
	BaseEvent
	Args []byte
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

func (e Event) ArgsString() string {
	return string(bytes.TrimRight(e.Args[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	time       bool
	timestamp  bool
	fails      bool
	uid        uint
	quote      bool
	name       string
	line       string
	printUid   bool
	maxArgs    uint
	verbose    bool
	cgroup     string
}

var opts = Options{
	bpfObjPath: "execsnoop.bpf.o",
	time:       false,
	timestamp:  false,
	fails:      false,
	uid:        0,
	quote:      false,
	name:       "",
	line:       "",
	printUid:   false,
	maxArgs:    20,
	verbose:    false,
	cgroup:     "",
}
var startTime time.Time

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.time, "time", "T", opts.time, "include time column on output (HH:MM:SS)")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "include timestamp on output")
	flag.BoolVarP(&opts.fails, "fails", "x", opts.fails, "include failed exec()s")
	flag.UintVarP(&opts.uid, "uid", "u", opts.uid, "trace this UID only")
	flag.BoolVarP(&opts.quote, "quote", "q", opts.quote, "Add quotemarks (\") around arguments")
	flag.StringVarP(&opts.name, "name", "n", opts.name, "only print commands matching this name, any arg")
	flag.StringVarP(&opts.line, "line", "l", opts.line, "only print commands where arg contains this line")
	flag.BoolVarP(&opts.printUid, "print-uid", "U", opts.printUid, "print UID column")
	flag.UintVar(&opts.maxArgs, "max-args", opts.maxArgs, "maximum number of arguments parsed and displayed, defaults to 20")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func checkArgs() {
	if opts.maxArgs > TotalMaxArgs {
		log.Fatalf("Invalid MAX_ARGS %d, should be in [1, %d] range", opts.maxArgs, TotalMaxArgs)
	}
}

func initGlobalVariable(bpfModule *bpf.Module, name string, value interface{}) {
	err := bpfModule.InitGlobalVariable(name, value)
	if err != nil {
		log.Fatalf("init global variable %s with value %v failed: %s", name, value, err)
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

func quotedSymbol(c byte) string {
	switch c {
	case '"':
		return `\"`
	case '\t':
		return `\t`
	case '\n':
		return `\n`
	default:
		return string(c)
	}
}

func formatArgs(event Event) string {
	var argsCount uint32
	var i uint32
	builder := strings.Builder{}

	if opts.quote {
		builder.WriteString(`"`)
	}
	for ; i < event.ArgsSize && argsCount < event.ArgsCount; i++ {
		c := event.Args[i]
		if opts.quote {
			if c == '\x00' {
				argsCount++
				builder.WriteString(`"`)
				builder.WriteString(" ")
				if argsCount < event.ArgsCount {
					builder.WriteString(`"`)
				}
			} else {
				builder.WriteString(quotedSymbol(c))
			}
		} else {
			if c == '\x00' {
				argsCount++
				builder.WriteString(" ")
			} else {
				builder.WriteByte(c)
			}
		}
	}
	if uint(argsCount) > opts.maxArgs {
		builder.WriteString(" ...")
	}
	return builder.String()
}

func formatEvent(event Event) {
	if opts.name != "" && !strings.Contains(event.CommString(), opts.name) {
		return
	}
	if opts.line != "" && !strings.Contains(event.ArgsString(), opts.line) {
		return
	}
	if opts.time {
		fmt.Printf("%-8s ", time.Now().Format("15:04:05"))
	}
	if opts.timestamp {
		timeDiff := time.Since(startTime).Seconds()
		fmt.Printf("%-8.3f", timeDiff)
	}
	if opts.printUid {
		fmt.Printf("%-6d", event.Uid)
	}
	fmt.Printf("%-16s %-6d %-6d %3d ", event.CommString(), event.Pid, event.Ppid, event.Retval)
	fmt.Printf("%s\n", formatArgs(event))
}

func main() {
	flag.Parse()
	checkArgs()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVariable(bpfModule, "ignore_failed", !opts.fails)
	if opts.uid > 0 {
		initGlobalVariable(bpfModule, "targ_uid", uint32(opts.uid))
	}
	initGlobalVariable(bpfModule, "max_args", uint32(opts.maxArgs))
	initGlobalVariable(bpfModule, "filter_cg", opts.cgroup != "")
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	initFilters(bpfModule)

	startTime = time.Now()
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

	if opts.time {
		fmt.Printf("%-9s", "TIME")
	}
	if opts.timestamp {
		fmt.Printf("%-8s ", "TIME(s)")
	}
	if opts.printUid {
		fmt.Printf("%-6s ", "UID")
	}
	fmt.Printf("%-16s %-6s %-6s %3s %s\n", "PCOMM", "PID", "PPID", "RET", "ARGS")

loop:
	for {
		select {
		case data := <-eventsChannel:
			var event Event
			err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event.BaseEvent)
			if err != nil {
				log.Fatalf("read data failed: %s\n%v", err, data)
			}
			event.Args = append(event.Args, data[40:]...)
			formatEvent(event)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
