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

const (
	TASK_COMM_LEN = 16
	DISK_NAME_LEN = 32
	MAX_SLOTS     = 20
)

type Hist struct {
	Slots [MAX_SLOTS]uint32
}

type HistKey struct {
	Comm [TASK_COMM_LEN]byte
}

func (k HistKey) CommString() string {
	return string(bytes.TrimRight(k.Comm[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	disk       string
	comm       string
	interval   uint64
	times      uint64
}

const maxCpuNr = 128

var opts = Options{
	bpfObjPath: "bitesize.bpf.o",
	verbose:    false,
	timestamp:  false,
	disk:       "",
	comm:       "",
	interval:   99999999,
	times:      99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.StringVarP(&opts.disk, "disk", "d", opts.disk, "Trace this disk only")
	flag.StringVarP(&opts.comm, "comm", "c", opts.comm, "Trace this comm only")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
	if args := flag.Args(); len(args) > 0 {
		interval, err := strconv.Atoi(args[0])
		if err != nil || interval <= 0 {
			log.Fatal("invalid internal\n")
		}
		opts.interval = uint64(interval)
		if len(args) > 1 {
			times, err := strconv.Atoi(args[1])
			if err != nil || times <= 0 {
				log.Fatal("invalid times\n")
			}
			opts.times = uint64(times)
		}
	}
}
func initGlobalVars(bpfModule *bpf.Module, partitions common.Partitions) {
	if opts.comm != "" {
		length := len(opts.comm)
		if length > TASK_COMM_LEN {
			length = TASK_COMM_LEN
		}
		value := [TASK_COMM_LEN]byte{}
		for i, v := range []byte(opts.comm[:length]) {
			value[i] = v
		}
		if err := bpfModule.InitGlobalVariable("targ_comm", value); err != nil {
			log.Fatalln(err)
		}
	}
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

func printLog2Hists(hists *bpf.BPFMap) {
	iter := hists.Iterator()
	for iter.Next() {
		key := iter.Key()
		var nextKey HistKey
		if err := binary.Read(bytes.NewReader(key), binary.LittleEndian, &nextKey); err != nil {
			log.Fatalf("failed to lookup hist: %s", err)
		}
		value, err := hists.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			log.Fatalf("failed to lookup hist: %s", err)
		}
		var hist Hist
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &hist); err != nil {
			log.Fatalln(err)
		}

		var vals []int
		for _, v := range hist.Slots {
			vals = append(vals, int(v))
		}
		fmt.Printf("\nProcess Name = %s\n", nextKey.CommString())
		common.PrintLog2Hist(vals, "Kbytes")
	}

	iter = hists.Iterator()
	for iter.Next() {
		key := iter.Key()
		if err := hists.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			log.Fatalf("failed to cleanup hist: %s", err)
		}
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

	hists, err := bpfModule.GetMap("hists")
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()
	ticker := time.NewTicker(time.Second * time.Duration(opts.interval))
	var end bool
	times := opts.times
	fmt.Printf("Tracing block device I/O... Hit Ctrl-C to end.\n")

loop:
	for {
		select {
		case <-ctx.Done():
			end = true
			break
		case <-ticker.C:
			break
		}

		fmt.Printf("\n")
		if opts.timestamp {
			ts := time.Now().Format("15:04:05")
			fmt.Printf("%-8s\n", ts)
		}
		printLog2Hists(hists)

		times--
		if end || times == 0 {
			break loop
		}
	}
}
