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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	TASK_COMM_LEN = 16
	MAX_SLOTS     = 20
	MAX_STACK     = 20
)

type Rqinfo struct {
	Pid           uint32
	KernStackSize uint32
	KernStack     [MAX_STACK]uint64
	Comm          [TASK_COMM_LEN]byte
	Dev           uint32
}

type Hist struct {
	Slots [MAX_SLOTS]uint32
}

type Options struct {
	bpfObjPath   string
	verbose      bool
	milliseconds bool
	disk         string
	duration     uint64
}

var opts = Options{
	bpfObjPath:   "biostacks.bpf.o",
	verbose:      false,
	milliseconds: false,
	disk:         "",
	duration:     0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.milliseconds, "milliseconds", "m", opts.milliseconds, "Millisecond histogram")
	flag.StringVarP(&opts.disk, "disk", "d", opts.disk, "Trace this disk only")
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
}
func initGlobalVars(bpfModule *bpf.Module, partitions common.Partitions) {
	if opts.disk != "" {
		p := partitions.GetByName(opts.disk)
		if p == nil {
			log.Fatalln("invaild partition name: not exist")
		}
		if err := bpfModule.InitGlobalVariable("filter_dev", true); err != nil {
			log.Fatalln(err)
		}
		if err := bpfModule.InitGlobalVariable("targ_dev", uint32(p.Dev)); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.milliseconds {
		if err := bpfModule.InitGlobalVariable("targ_ms", true); err != nil {
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
	programNames := []string{
		"blk_account_io_start", "blk_account_io_done", "blk_account_io_merge_bio",
	}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if !common.Contains(programNames, prog.Name()) {
			continue
		}
		_, err := prog.AttachGeneric()
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func printMap(hists *bpf.BPFMap, partitions common.Partitions, ksyms common.Ksyms) {
	units := "usecs"
	if opts.milliseconds {
		units = "msecs"
	}
	items, err := common.DumpHash(hists)
	if err != nil {
		log.Fatalln(err)
	}
	for _, ret := range items {
		var key Rqinfo
		if err := binary.Read(bytes.NewReader(ret[0]), binary.LittleEndian, &key); err != nil {
			log.Fatalln(err)
		}
		var hist Hist
		if err := binary.Read(bytes.NewReader(ret[1]), binary.LittleEndian, &hist); err != nil {
			log.Fatalln(err)
		}
		name := "Unknown"
		if p := partitions.GetByDev(int(key.Dev)); p != nil {
			name = p.Name
		}
		fmt.Printf("%-14.14s %-6d %-7s\n",
			common.GoString(key.Comm[:]), key.Pid, name)
		for _, addr := range key.KernStack {
			name := "Unknown"
			if k := ksyms.MapAddr(addr); k != nil {
				name = k.Name
			}
			fmt.Printf("%s\n", name)
		}
		var vals []int
		for _, s := range hist.Slots {
			vals = append(vals, int(s))
		}
		common.PrintLog2Hist(vals, units)
		fmt.Printf("\n")
	}
}

func main() {
	parseArgs()

	partitions, err := common.LoadPartitions()
	if err != nil {
		log.Fatalln(err)
	}

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule, *partitions)
	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
	attachPrograms(bpfModule)

	ksyms, err := common.LoadKsyms()
	if err != nil {
		log.Fatalln(err)
	}
	hists, err := bpfModule.GetMap("hists")
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancel()
	}

	fmt.Printf("Tracing block I/O with init stacks. Hit Ctrl-C to end.\n")
	<-ctx.Done()

	printMap(hists, *partitions, *ksyms)
}
