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
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

type Hist struct {
	Slots [36]uint32
	Comm  [16]byte
}

func (h Hist) CommString() string {
	return string(bytes.TrimRight(h.Comm[:], "\x00"))
}

type Options struct {
	bpfObjPath   string
	verbose      bool
	offcpu       bool
	timestamp    bool
	milliseconds bool
	cgroup       string
	pids         bool
	tids         bool
	pid          uint32
	interval     uint
	times        uint
}

var opts = Options{
	bpfObjPath:   "cpudist.bpf.o",
	verbose:      false,
	offcpu:       false,
	timestamp:    false,
	milliseconds: false,
	cgroup:       "",
	pids:         false,
	tids:         false,
	pid:          0,
	interval:     99999999,
	times:        99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.offcpu, "offcpu", "O", opts.offcpu, "Measure off-CPU time")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.milliseconds, "milliseconds", "m", opts.milliseconds, "Millisecond histogram")
	flag.BoolVarP(&opts.pids, "pids", "P", opts.pids, "Print a histogram per process ID")
	flag.BoolVarP(&opts.tids, "tids", "L", opts.tids, "Print a histogram per thread ID")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Trace this PID only")
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
		opts.interval = uint(interval)
		if len(args) > 1 {
			times, err := strconv.Atoi(args[1])
			if err != nil || times <= 0 {
				log.Fatal("invalid times\n")
			}
			opts.times = uint(times)
		}
	}
}

func getPidMax() (int, error) {
	data, err := os.ReadFile("/proc/sys/kernel/pid_max")
	if err != nil {
		return 0, err
	}
	line := strings.TrimSpace(string(data))
	value, err := strconv.Atoi(line)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.cgroup != "" {
		if err := bpfModule.InitGlobalVariable("filter_cg", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.pids {
		if err := bpfModule.InitGlobalVariable("targ_per_process", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.tids {
		if err := bpfModule.InitGlobalVariable("targ_per_thread", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.offcpu {
		if err := bpfModule.InitGlobalVariable("targ_offcpu", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.milliseconds {
		if err := bpfModule.InitGlobalVariable("milliseconds", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_tgid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
}

func loadBPFObj(bpfModule *bpf.Module) {
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
}
func resizeMap(bpfModule *bpf.Module, name string, size int) {
	m, err := bpfModule.GetMap(name)
	if err != nil {
		log.Fatalln(err)
	}
	if err := m.Resize(uint32(size)); err != nil {
		log.Fatalln(err)
	}
}

func resizeMaps(bpfModule *bpf.Module) {
	pidMax, err := getPidMax()
	if err != nil || pidMax < 0 {
		log.Fatalf("failed to get pid_max: %s", err)
	}
	resizeMap(bpfModule, "start", pidMax)
	if !(opts.pids || opts.tids) {
		resizeMap(bpfModule, "hists", 1)
	} else {
		resizeMap(bpfModule, "hists", pidMax)
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
	units := "usecs"
	if opts.milliseconds {
		units = "msecs"
	}
	iter := hists.Iterator()
	for iter.Next() {
		key := iter.Key()
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
		nextKey := binary.LittleEndian.Uint32(key)
		if opts.pids {
			fmt.Printf("\npid = %d %s\n", nextKey, hist.CommString())
		}
		if opts.tids {
			fmt.Printf("\ntid = %d %s\n", nextKey, hist.CommString())
		}
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

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	initGlobalVars(bpfModule)
	resizeMaps(bpfModule)
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
	action := "on"
	if opts.offcpu {
		action = "off"
	}
	fmt.Printf("Tracing %s-CPU time... Hit Ctrl-C to end.\n", action)

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
