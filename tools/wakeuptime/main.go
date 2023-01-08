package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const TASK_COMM_LEN = 16

type KeyT struct {
	Waker     [TASK_COMM_LEN]byte
	Target    [TASK_COMM_LEN]byte
	WKStackId uint32
}

type Options struct {
	bpfObjPath        string
	verbose           bool
	pid               uint32
	userThreadsOnly   bool
	perfMaxStackDepth uint32
	stackStorageSize  uint32
	minBlockTime      uint64
	maxBlockTime      uint64
	duration          uint64
}

var opts = Options{
	bpfObjPath:        "wakeuptime.bpf.o",
	pid:               0,
	verbose:           false,
	userThreadsOnly:   false,
	perfMaxStackDepth: 127,
	stackStorageSize:  1024,
	minBlockTime:      1,
	maxBlockTime:      0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "trace this PID only")
	flag.BoolVarP(&opts.userThreadsOnly, "user-threads-only", "u", opts.userThreadsOnly,
		"user threads only (no kernel threads)")
	flag.Uint32Var(&opts.perfMaxStackDepth, "perf-max-stack-depth", opts.perfMaxStackDepth,
		"the limit for both kernel and user stack traces (default 127)")
	flag.Uint32Var(&opts.stackStorageSize, "stack-storage-size", opts.stackStorageSize,
		"the number of unique stack traces that can be stored and displayed (default 1024)")
	flag.Uint64VarP(&opts.minBlockTime, "min-block-time", "m", opts.minBlockTime,
		"the amount of time in microseconds over which we store traces (default 1)")
	flag.Uint64VarP(&opts.maxBlockTime, "max-block-time", "M", opts.maxBlockTime,
		"the amount of time in microseconds under which we store traces (default U64_MAX)")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
	if args := flag.Args(); len(args) > 0 {
		duration, err := strconv.Atoi(args[0])
		if err != nil || duration <= 0 {
			log.Fatalf("invalid delay (in us): %s\n", args[0])
		}
		opts.duration = uint64(duration)
	}

	if opts.maxBlockTime > 0 && opts.minBlockTime > opts.maxBlockTime {
		log.Fatalln("min-block-time should be smaller than max-block-time")
	}
	if opts.userThreadsOnly && opts.pid > 0 {
		log.Fatalln("use either -u or -p")
	}
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.minBlockTime > 0 {
		if err := bpfModule.InitGlobalVariable("min_block_ns", opts.minBlockTime*1000); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.maxBlockTime > 0 {
		if err := bpfModule.InitGlobalVariable("max_block_ns", opts.maxBlockTime*1000); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.userThreadsOnly {
		if err := bpfModule.InitGlobalVariable("user_threads_only", true); err != nil {
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

func printMap(counts, stackmap *bpf.BPFMap, ksyms common.Ksyms) {
	items, err := common.DumpHash(counts)
	if err != nil {
		log.Fatalf("failed to lookup info: %+v", err)
	}

	for _, item := range items {
		rawKey := item[0]
		rawValue := item[1]
		var key KeyT
		var value uint64
		if err := binary.Read(bytes.NewReader(rawKey), binary.LittleEndian, &key); err != nil {
			log.Fatalln(err)
		}
		if err := binary.Read(bytes.NewReader(rawValue), binary.LittleEndian, &value); err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("\n\t%-16s %s\n", "target:", key.Target)

		rawKernStack, err := stackmap.GetValue(unsafe.Pointer(&key.WKStackId))
		if err != nil {
			log.Printf("missed kernel stack: %+v", err)
			continue
		}
		kernStacks := make([]uint64, opts.perfMaxStackDepth)
		for i := 0; i < int(opts.perfMaxStackDepth); i += 8 {
			v := rawKernStack[i : i+8]
			kernStacks = append(kernStacks, binary.LittleEndian.Uint64(v))
		}
		for _, addr := range kernStacks {
			if addr == 0 {
				continue
			}
			name := "Unknown"
			if v := ksyms.MapAddr(addr); v != nil {
				name = v.Name
			}
			fmt.Printf("\t%-16x %s\n", addr, name)
		}
		fmt.Printf("\t%16s %s\n", "waker:", key.Waker)

		value /= 1000
		fmt.Printf("\t%d\n", value)
	}
}

func main() {
	parseArgs()

	ksyms, err := common.LoadKsyms()
	if err != nil {
		log.Fatalln(err)
	}

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule)
	stackmap, err := bpfModule.GetMap("stackmap")
	if err != nil {
		log.Fatalln(err)
	}
	if err := stackmap.SetValueSize(opts.perfMaxStackDepth * 8); err != nil {
		log.Fatalln(err)
	}
	if err := stackmap.Resize(opts.stackStorageSize); err != nil {
		log.Fatalln(err)
	}

	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
	attachPrograms(bpfModule)

	counts, err := bpfModule.GetMap("counts")
	if err != nil {
		log.Fatalln(err)
	}
	if stackmap, err = bpfModule.GetMap("stackmap"); err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancel()
	}

	fmt.Printf("Tracing blocked time (us) by kernel stack\n")
	<-ctx.Done()

	printMap(counts, stackmap, *ksyms)
}
