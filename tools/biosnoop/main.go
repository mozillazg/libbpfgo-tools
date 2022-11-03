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

type Event struct {
	Comm     [16]byte
	Delta    uint64
	Qdelta   uint64
	Ts       uint64
	Sector   uint64
	Len      uint32
	Pid      uint32
	CmdFlags uint32
	Dev      uint32
}

func (e Event) CommString() string {
	flag.Usage()
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	queued     bool
	disk       string
	duration   uint64
	cgroup     string
}

var opts = Options{
	bpfObjPath: "biosnoop.bpf.o",
	verbose:    false,
	timestamp:  false,
	queued:     false,
	disk:       "",
	duration:   0,
	cgroup:     "",
}

var startTs uint64

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.queued, "queued", "Q", opts.queued, "Include OS queued time in I/O time")
	flag.StringVarP(&opts.disk, "disk", "d", opts.disk, "Trace this disk only")
	flag.StringVarP(&opts.cgroup, "cgroup", "c", opts.cgroup, "Trace process in cgroup path")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
	if args := flag.Args(); len(args) > 0 {
		interval, err := strconv.Atoi(args[0])
		if err != nil || interval <= 0 {
			log.Fatalf("invalid delay (in us): %s\n", args[0])
		}
		opts.duration = uint64(interval)
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
	var disabledNames []string
	if !opts.queued {
		disabledNames = append(disabledNames, "block_rq_insert")
	}

	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		for _, name := range disabledNames {
			if prog.Name() == name {
				continue
			}
		}
		if _, err := prog.AttachGeneric(); err != nil {
			log.Fatalln(err)
		}
	}
}

func blkFillRwbs(op int) string {
	rwbs := bytes.Buffer{}
	if op&common.REQ_PREFLUSH > 0 {
		rwbs.WriteByte('F')
	}
	switch op & common.REQ_OP_MASK {
	case common.REQ_OP_WRITE, common.REQ_OP_WRITE_SAME:
		rwbs.WriteByte('W')
		break
	case common.REQ_OP_DISCARD:
		rwbs.WriteByte('D')
		break
	case common.REQ_OP_SECURE_ERASE:
		rwbs.WriteByte('D')
		rwbs.WriteByte('E')
		break
	case common.REQ_OP_FLUSH:
		rwbs.WriteByte('F')
		break
	case common.REQ_OP_READ:
		rwbs.WriteByte('R')
		break
	default:
		rwbs.WriteByte('N')
	}

	if (op & common.REQ_FUA) > 0 {
		rwbs.WriteByte('F')
	}
	if (op & common.REQ_RAHEAD) > 0 {
		rwbs.WriteByte('A')
	}
	if (op & common.REQ_SYNC) > 0 {
		rwbs.WriteByte('S')
	}
	if (op & common.REQ_META) > 0 {
		rwbs.WriteByte('M')
	}

	return rwbs.String()
}

func printEvent(data []byte, partitions common.Partitions) {
	var e Event
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		log.Fatalln(err)
	}
	rwbs := blkFillRwbs(int(e.CmdFlags))
	name := "Unknown"
	if partition := partitions.GetByDev(int(e.Dev)); partition != nil {
		name = partition.Name
	}
	if startTs == 0 {
		startTs = e.Ts
	}
	fmt.Printf("%-11.6f %-14.14s %-7d %-7s %-4s %-10d %-7d ",
		float64(e.Ts-startTs)/1000000000.0,
		e.CommString(), e.Pid, name, rwbs, e.Sector, e.Len)
	if opts.queued {
		fmt.Printf("%7.3f ", float64(e.Qdelta)/1000000.0)
	}
	fmt.Printf("%7.3f\n", float64(e.Delta)/1000000.0)
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

	fmt.Printf("%-11s %-14s %-7s %-7s %-4s %-10s %-7s ",
		"TIME(s)", "COMM", "PID", "DISK", "T", "SECTOR", "BYTES")
	if opts.queued {
		fmt.Printf("%7s ", "QUE(ms)")
	}
	fmt.Printf("%7s\n", "LAT(ms)")

	if opts.duration > 0 {
		var cancelFunc context.CancelFunc
		ctx, cancelFunc = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancelFunc()
	}
loop:
	for {
		select {
		case data := <-eventsChannel:
			printEvent(data, *partitions)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
