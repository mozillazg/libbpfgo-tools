package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const TASK_COMM_LEN = 16

type Data struct {
	Count   uint64
	TotalNs uint64
	Comm    [TASK_COMM_LEN]byte
}

type DataExt struct {
	Data
	key uint32
}

type Options struct {
	bpfObjPath   string
	verbose      bool
	pid          uint32
	interval     uint
	duration     uint
	top          uint
	cgroup       string
	failures     bool
	latency      bool
	milliseconds bool
	process      bool
	errno        int
	list         bool
}

var opts = Options{
	bpfObjPath:   "syscount.bpf.o",
	verbose:      false,
	pid:          0,
	interval:     0,
	duration:     0,
	top:          10,
	cgroup:       "",
	failures:     false,
	latency:      false,
	milliseconds: false,
	process:      false,
	errno:        0,
	list:         false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process PID to trace")
	flag.UintVarP(&opts.interval, "interval", "i", opts.interval,
		"Print summary at this interval (seconds), 0 for infinite wait (default)")
	flag.UintVarP(&opts.duration, "duration", "d", opts.duration, "Total tracing duration (seconds)")
	flag.UintVarP(&opts.top, "top", "T", opts.top, "Print only the top syscalls")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
	flag.BoolVarP(&opts.failures, "failures", "x", opts.failures, "Trace only failed syscalls")
	flag.BoolVarP(&opts.latency, "latency", "L", opts.latency, "Collect syscall latency")
	flag.BoolVarP(&opts.milliseconds, "milliseconds", "m", opts.milliseconds,
		"Display latency in milliseconds (default: microseconds)")
	flag.BoolVarP(&opts.process, "process", "P", opts.process, "Count by process and not by syscall")
	flag.IntVarP(&opts.errno, "errno", "e", opts.errno,
		"Trace only syscalls that return this error (numeric or EPERM, etc.)")
	flag.BoolVarP(&opts.list, "list", "l", opts.list, "Print list of recognized syscalls and exit")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("filter_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.failures {
		if err := bpfModule.InitGlobalVariable("filter_failed", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.latency {
		if err := bpfModule.InitGlobalVariable("measure_latency", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.process {
		if err := bpfModule.InitGlobalVariable("count_by_process", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.cgroup != "" {
		if err := bpfModule.InitGlobalVariable("filter_cg", true); err != nil {
			log.Fatalln(err)
		}
	}
	// TODO: filter_errno
}

func loadBPFObj(bpfModule *bpf.Module) {
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
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

func applyFilters(bpfModule *bpf.Module) {
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

func attachPrograms(bpfModule *bpf.Module) {
	names := []string{"sys_exit"}
	if opts.latency {
		names = append(names, "sys_enter")
	}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if !common.Contains(names, prog.Name()) {
			continue
		}
		if _, err := prog.AttachGeneric(); err != nil {
			log.Fatalln(err)
		}
	}
}

func printTimestamp() {
	now := time.Now()
	fmt.Printf("[%02d:%02d:%02d]\n", now.Hour(), now.Minute(), now.Second())
}

func getAggColName() string {
	if opts.process {
		return "PID    COMM"
	}
	return "SYSCALL"
}

func printLatencyHeader() {
	timeCol := "TIME (us)"
	if opts.milliseconds {
		timeCol = "TIME (ms)"
	}

	fmt.Printf("%-22s %8s %16s\n", getAggColName(), "COUNT", timeCol)
}

func printCountHeader() {
	fmt.Printf("%-22s %8s\n", getAggColName(), "COUNT")
}

func aggCol(val DataExt) string {
	var col string
	if opts.process {
		col = fmt.Sprintf("%-6d %-15s", val.key, common.GoString(val.Comm[:]))
	} else {
		col = common.SyscallName(int(val.key))
	}
	return col
}

func printLatency(vals []DataExt) {
	div := 1000.0
	if opts.milliseconds {
		div = 1000000.0
	}
	printLatencyHeader()
	count := int(opts.top)
	if count > len(vals) {
		count = len(vals)
	}
	for i := 0; i < count; i++ {
		fmt.Printf("%-22s %8d %16.3f\n",
			aggCol(vals[i]), vals[i].Count, float64(vals[i].TotalNs)/div)
	}
	fmt.Printf("\n")
}

func printCount(vals []DataExt) {
	printCountHeader()
	count := int(opts.top)
	if count > len(vals) {
		count = len(vals)
	}
	for i := 0; i < count; i++ {
		fmt.Printf("%-22s %8d\n", aggCol(vals[i]), vals[i].Count)
	}
	fmt.Printf("\n")
}

func printData(dataMap *bpf.BPFMap) {
	vals := readVals(dataMap)
	if len(vals) == 0 {
		return
	}
	if opts.latency {
		sortValsByLatency(vals)
	} else {
		sortValsByCount(vals)
	}

	printTimestamp()
	if opts.latency {
		printLatency(vals)
	} else {
		printCount(vals)
	}
}

func readVals(dataMap *bpf.BPFMap) []DataExt {
	items, err := common.DumpThenClearHash(dataMap)
	if err != nil {
		log.Fatalln(err)
	}
	var vals []DataExt
	for _, ret := range items {
		var key uint32
		if err := binary.Read(bytes.NewReader(ret[0]), binary.LittleEndian, &key); err != nil {
			log.Fatalln(err)
		}
		var value Data
		if err := binary.Read(bytes.NewReader(ret[1]), binary.LittleEndian, &value); err != nil {
			log.Fatalln(err)
		}
		vals = append(vals, DataExt{
			Data: value,
			key:  key,
		})
	}

	return vals
}

func sortValsByCount(vals []DataExt) {
	sort.Slice(vals, func(i, j int) bool {
		iC := vals[i].Count
		jC := vals[j].Count
		return iC > jC
	})
}

func sortValsByLatency(vals []DataExt) {
	sort.Slice(vals, func(i, j int) bool {
		iN := vals[i].TotalNs
		jN := vals[j].TotalNs
		return iN > jN
	})
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule)
	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
	attachPrograms(bpfModule)

	data, err := bpfModule.GetMap("data")
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var intervalC <-chan time.Time
	if opts.interval > 0 {
		ticket := time.NewTicker(time.Second * time.Duration(opts.interval))
		defer ticket.Stop()
		intervalC = ticket.C
	}
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancel()
	}
	var done bool

	fmt.Printf("Tracing syscalls, printing top %d... Ctrl+C to quit.\n", opts.top)

loop:
	for {
		select {
		case <-intervalC:
		case <-ctx.Done():
			done = true
		}

		printData(data)

		if done {
			break loop
		}
	}
}
