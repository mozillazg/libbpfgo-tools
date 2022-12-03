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

type Counter struct {
	LastSector uint64
	Bytes      uint64
	Sequential uint32
	Random     uint32
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	disk       string
	interval   uint64
	times      uint64
}

var opts = Options{
	bpfObjPath: "biopattern.bpf.o",
	verbose:    false,
	timestamp:  false,
	disk:       "",
	interval:   99999999,
	times:      99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.StringVarP(&opts.disk, "disk", "d", opts.disk, "Trace this disk only")
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

func printMap(hists *bpf.BPFMap, partitions common.Partitions) {
	iter := hists.Iterator()
	for iter.Next() {
		key := iter.Key()
		value, err := hists.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			log.Fatalf("failed to lookup counters: %s", err)
		}
		var counter Counter
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &counter); err != nil {
			log.Fatalln(err)
		}

		total := counter.Sequential + counter.Random
		if total <= 0 {
			continue
		}
		if opts.timestamp {
			ts := time.Now().Format("15:04:05")
			fmt.Printf("%-9s ", ts)
		}
		nextKey := binary.LittleEndian.Uint32(key)
		partition := partitions.GetByDev(int(nextKey))
		name := "Unknown"
		if partition != nil {
			name = partition.Name
		}
		fmt.Printf("%-7s %5d %5d %8d %10d\n", name,
			counter.Random*100/total, counter.Sequential*100/total, total,
			counter.Bytes/1024)
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

	counters, err := bpfModule.GetMap("counters")
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

	fmt.Printf("Tracing block device I/O requested seeks... Hit Ctrl-C to end.\n")
	if opts.timestamp {
		fmt.Printf("%-9s ", "TIME")
	}
	fmt.Printf("%-7s %5s %5s %8s %10s\n", "DISK", "%RND", "%SEQ",
		"COUNT", "KBYTES")

loop:
	for {
		select {
		case <-ctx.Done():
			end = true
			break
		case <-ticker.C:
			break
		}

		printMap(counters, *partitions)

		times--
		if end || times == 0 {
			break loop
		}
	}
}
