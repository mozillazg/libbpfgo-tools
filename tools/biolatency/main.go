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

type Hist struct {
	Slots [27]uint32
}

type HistKey struct {
	CmdFlags uint32
	Dev      uint32
}

type Options struct {
	bpfObjPath   string
	verbose      bool
	timestamp    bool
	queued       bool
	disk         bool
	flag         bool
	milliseconds bool
	diskName     string
	cgroup       string
	interval     uint64
	times        uint64
}

var opts = Options{
	bpfObjPath:   "biolatency.bpf.o",
	verbose:      false,
	timestamp:    false,
	queued:       false,
	disk:         false,
	flag:         false,
	milliseconds: false,
	diskName:     "",
	cgroup:       "",
	interval:     99999999,
	times:        99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.milliseconds, "milliseconds", "m", opts.milliseconds, "Millisecond histogram")
	flag.BoolVarP(&opts.queued, "queued", "Q", opts.queued, "Include OS queued time in I/O time")
	flag.BoolVarP(&opts.disk, "disk", "D", opts.disk, "Print a histogram per disk device")
	flag.StringVarP(&opts.diskName, "disk-name", "d", opts.diskName, "Trace this disk only")
	flag.BoolVarP(&opts.flag, "flag", "F", opts.flag, "Print a histogram per set of I/O flags")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
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
	if opts.diskName != "" {
		p := partitions.GetByName(opts.diskName)
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
	if opts.disk {
		if err := bpfModule.InitGlobalVariable("targ_per_disk", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.flag {
		if err := bpfModule.InitGlobalVariable("targ_per_flag", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.milliseconds {
		if err := bpfModule.InitGlobalVariable("targ_ms", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.queued {
		if err := bpfModule.InitGlobalVariable("targ_queued", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.cgroup != "" {
		if err := bpfModule.InitGlobalVariable("filter_cg", true); err != nil {
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
	if opts.cgroup != "" {
		idx := 0
		cgroupFd, err := common.GetCgroupDirFD(opts.cgroup)
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

func attachPrograms(bpfModule *bpf.Module) {
	names := []string{"block_rq_issue", "block_rq_complete"}
	if opts.queued {
		names = append(names, "block_rq_insert")
	}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		for _, n := range names {
			if prog.Name() == n {
				_, err := prog.AttachGeneric()
				if err != nil {
					log.Fatalln(err)
				}
			}
		}
	}
}

func printCmdFlags(cmdFlags int) {
	var flags = []struct {
		bit int
		str string
	}{
		{common.REQ_NOWAIT, "NoWait-"},
		{common.REQ_BACKGROUND, "Background-"},
		{common.REQ_RAHEAD, "ReadAhead-"},
		{common.REQ_PREFLUSH, "PreFlush-"},
		{common.REQ_FUA, "FUA-"},
		{common.REQ_INTEGRITY, "Integrity-"},
		{common.REQ_IDLE, "Idle-"},
		{common.REQ_NOMERGE, "NoMerge-"},
		{common.REQ_PRIO, "Priority-"},
		{common.REQ_META, "Metadata-"},
		{common.REQ_SYNC, "Sync-"},
	}
	var ops = make([]string, common.REQ_OP_LAST+1)
	ops[common.REQ_OP_READ] = "Read"
	ops[common.REQ_OP_WRITE] = "Write"
	ops[common.REQ_OP_FLUSH] = "Flush"
	ops[common.REQ_OP_DISCARD] = "Discard"
	ops[common.REQ_OP_SECURE_ERASE] = "SecureErase"
	ops[common.REQ_OP_ZONE_RESET] = "ZoneReset"
	ops[common.REQ_OP_WRITE_SAME] = "WriteSame"
	ops[common.REQ_OP_ZONE_RESET_ALL] = "ZoneResetAll"
	ops[common.REQ_OP_WRITE_ZEROES] = "WriteZeroes"
	ops[common.REQ_OP_ZONE_OPEN] = "ZoneOpen"
	ops[common.REQ_OP_ZONE_CLOSE] = "ZoneClose"
	ops[common.REQ_OP_ZONE_FINISH] = "ZoneFinish"
	ops[common.REQ_OP_SCSI_IN] = "SCSIIn"
	ops[common.REQ_OP_SCSI_OUT] = "SCSIOut"
	ops[common.REQ_OP_DRV_IN] = "DrvIn"
	ops[common.REQ_OP_DRV_OUT] = "DrvOut"

	fmt.Printf("flags = ")
	for _, v := range flags {
		if cmdFlags&v.bit > 0 {
			fmt.Printf("%s", v.str)
		}
	}
	if (cmdFlags & common.REQ_OP_MASK) < len(ops) {
		fmt.Printf("%s", ops[cmdFlags&common.REQ_OP_MASK])
	} else {
		fmt.Printf("Unknown")
	}

}

func printLog2Hists(hists *bpf.BPFMap, partitions common.Partitions) {
	units := "usecs"
	if opts.milliseconds {
		units = "msecs"
	}
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
		if opts.disk {
			disk := "Unknown"
			if p := partitions.GetByDev(int(nextKey.Dev)); p != nil {
				disk = p.Name
			}
			fmt.Printf("\ndisk = %s\t", disk)
		}
		if opts.flag {
			printCmdFlags(int(nextKey.CmdFlags))
		}
		fmt.Printf("\n")
		common.PrintLog2Hist(vals, units)
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
		printLog2Hists(hists, *partitions)

		times--
		if end || times == 0 {
			break loop
		}
	}
}
