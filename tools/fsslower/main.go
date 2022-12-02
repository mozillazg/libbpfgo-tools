package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	FILE_NAME_LEN = 32
	TASK_COMM_LEN = 16
)

const (
	READ = iota
	WRITE
	OPEN
	FSYNC
	MAX_OP
)

const (
	NONE = iota
	BTRFS
	EXT4
	NFS
	XFS
)

type Event struct {
	DeltaUs uint64
	EndNs   uint64
	Offset  uint64
	Size    uint64
	Pid     uint32
	Op      uint32
	File    [FILE_NAME_LEN]byte
	Task    [TASK_COMM_LEN]byte
}

type FSConfig struct {
	fs      string
	opFuncs [MAX_OP]string
}

type Options struct {
	bpfObjPath string
	verbose    bool
	csv        bool
	pid        uint32
	_type      string
	min        uint
	duration   uint64
	fsType     int
}

var fileSystemTypes = map[string]int{
	"btrfs": BTRFS,
	"ext4":  EXT4,
	"nfs":   NFS,
	"xfs":   XFS,
}

var aliasTypes = map[string]int{
	"btrfsdist": BTRFS,
	"ext4dist":  EXT4,
	"nfsdist":   NFS,
	"xfsdist":   XFS,
}

var fsConfigs [XFS + 1]FSConfig
var fileOpNames [MAX_OP]string
var opts = Options{
	bpfObjPath: "fsslower.bpf.o",
	verbose:    false,
	csv:        false,
	pid:        0,
	_type:      "",
	min:        10,
	duration:   0,
	fsType:     -1,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.csv, "cvs", "c", opts.csv, "Output as csv")
	flag.UintVarP(&opts.min, "min", "m", opts.min, "Min latency to trace, in ms")
	flag.Uint64VarP(&opts.duration, "duration", "d", opts.duration, "Total duration of trace in seconds")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.StringVarP(&opts._type, "type", "t", opts._type, "Which filesystem to trace, [btrfs/ext4/nfs/xfs]")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")

	initFSConfigs()
	initFileOpsNames()
}

func parseArgs() {
	flag.Parse()

	if v, ok := fileSystemTypes[opts._type]; !ok {
		if opts.fsType < 0 {
			log.Fatalln("invalid filesystem")
		}
	} else {
		opts.fsType = v
	}
	if opts.fsType == 0 {
		log.Fatalln("filesystem must be specified using -t option")
	}
}

func initFSConfigs() {
	fsConfigs[BTRFS] = FSConfig{
		fs: "btrfs",
	}
	fsConfigs[BTRFS].opFuncs[READ] = "btrfs_file_read_iter"
	fsConfigs[BTRFS].opFuncs[WRITE] = "btrfs_file_write_iter"
	fsConfigs[BTRFS].opFuncs[OPEN] = "btrfs_file_open"
	fsConfigs[BTRFS].opFuncs[FSYNC] = "btrfs_sync_file"

	fsConfigs[EXT4] = FSConfig{
		fs: "ext4",
	}
	fsConfigs[EXT4].opFuncs[READ] = "ext4_file_read_iter"
	fsConfigs[EXT4].opFuncs[WRITE] = "ext4_file_write_iter"
	fsConfigs[EXT4].opFuncs[OPEN] = "ext4_file_open"
	fsConfigs[EXT4].opFuncs[FSYNC] = "ext4_sync_file"

	fsConfigs[NFS] = FSConfig{
		fs: "nfs",
	}
	fsConfigs[NFS].opFuncs[READ] = "nfs_file_read"
	fsConfigs[NFS].opFuncs[WRITE] = "nfs_file_write"
	fsConfigs[NFS].opFuncs[OPEN] = "nfs_file_open"
	fsConfigs[NFS].opFuncs[FSYNC] = "nfs_file_fsync"

	fsConfigs[XFS] = FSConfig{
		fs: "xfs",
	}
	fsConfigs[XFS].opFuncs[READ] = "xfs_file_read_iter"
	fsConfigs[XFS].opFuncs[WRITE] = "xfs_file_write_iter"
	fsConfigs[XFS].opFuncs[OPEN] = "xfs_file_open"
	fsConfigs[XFS].opFuncs[FSYNC] = "xfs_file_fsync"
}

func initFileOpsNames() {
	fileOpNames[READ] = "R"
	fileOpNames[WRITE] = "W"
	fileOpNames[OPEN] = "O"
	fileOpNames[FSYNC] = "F"
}

func aliasParse(name string) {
	name = path.Base(name)
	if v, ok := aliasTypes[name]; ok {
		opts.fsType = v
	}
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("target_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if err := bpfModule.InitGlobalVariable("min_lat_ns", uint64(opts.min*1000*1000)); err != nil {
		log.Fatalln(err)
	}
}

func loadBPFObj(bpfModule *bpf.Module) {
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
}

func applyFilters(bpfModule *bpf.Module) {
}

func attachPrograms(bpfModule *bpf.Module, names []string) {
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

func fentrySetAttachTarget(bpfModule *bpf.Module) []string {
	var programNames []string
	cfg := fsConfigs[opts.fsType]
	fentrySetAttach(bpfModule, "file_read_fentry", cfg.opFuncs[READ])
	programNames = append(programNames, "file_read_fentry")

	fentrySetAttach(bpfModule, "file_read_fexit", cfg.opFuncs[READ])
	programNames = append(programNames, "file_read_fexit")

	fentrySetAttach(bpfModule, "file_write_fentry", cfg.opFuncs[WRITE])
	programNames = append(programNames, "file_write_fentry")

	fentrySetAttach(bpfModule, "file_write_fexit", cfg.opFuncs[WRITE])
	programNames = append(programNames, "file_write_fexit")

	fentrySetAttach(bpfModule, "file_open_fentry", cfg.opFuncs[OPEN])
	programNames = append(programNames, "file_open_fentry")

	fentrySetAttach(bpfModule, "file_open_fexit", cfg.opFuncs[OPEN])
	programNames = append(programNames, "file_open_fexit")

	fentrySetAttach(bpfModule, "file_sync_fentry", cfg.opFuncs[FSYNC])
	programNames = append(programNames, "file_sync_fentry")

	fentrySetAttach(bpfModule, "file_sync_fexit", cfg.opFuncs[FSYNC])
	programNames = append(programNames, "file_sync_fexit")

	return programNames
}

func fentrySetAttach(bpfModule *bpf.Module, funcName, target string) {
	prog, err := bpfModule.GetProgram(funcName)
	if err != nil {
		log.Fatalln(err)
	}
	prog.SetProgramType(bpf.BPFProgTypeTracing)
	if strings.HasSuffix(funcName, "_fentry") {
		prog.SetAttachType(bpf.BPFAttachTypeTraceFentry)
	} else {
		prog.SetAttachType(bpf.BPFAttachTypeTraceFexit)
	}
	if err := prog.SetAttachTarget(0, target); err != nil {
		log.Fatalln(err)
	}
}

func printHeader() {
	fs := fsConfigs[opts.fsType].fs

	if opts.csv {
		fmt.Printf("ENDTIME_ns,TASK,PID,TYPE,BYTES,OFFSET_b,LATENCY_us,FILE\n")
		return
	}

	if opts.min > 0 {
		fmt.Printf("Tracing %s operations slower than %d ms", fs, opts.min)
	} else {
		fmt.Printf("Tracing %s operations", fs)
	}

	if opts.duration > 0 {
		fmt.Printf(" for %d secs.\n", opts.duration)
	} else {
		fmt.Printf("... Hit Ctrl-C to end.\n")
	}

	fmt.Printf("%-8s %-16s %-7s %1s %-7s %-8s %7s %s\n",
		"TIME", "COMM", "PID", "T", "BYTES", "OFF_KB", "LAT(ms)", "FILENAME")
}

func printEvent(data []byte) {
	var e Event
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
		log.Fatalln(err)
	}
	if opts.csv {
		fmt.Printf("%d,%s,%d,%c,", e.EndNs, common.GoString(e.Task[:]), e.Pid, fileOpNames[e.Op])
		if e.Size >= math.MaxInt32 {
			fmt.Printf("LL_MAX,")
		} else {
			fmt.Printf("%d,", e.Size)
			fmt.Printf("%d,%d,%s\n", e.Offset, e.DeltaUs, common.GoString(e.File[:]))
			return
		}
	}

	ts := time.Now().Format("15:04:05")
	fmt.Printf("%-8s %-16s %-7d %s ", ts, common.GoString(e.Task[:]), e.Pid, fileOpNames[e.Op])
	if e.Size >= math.MaxInt32 {
		fmt.Printf("%-7s ", "LL_MAX")
	} else {
		fmt.Printf("%-7d ", e.Size)
	}
	fmt.Printf("%-8d %7.2f %s\n", e.Offset/1024, (float64(e.DeltaUs) / 1000), common.GoString(e.File[:]))
}

func main() {
	aliasParse(os.Args[0])
	parseArgs()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	names := fentrySetAttachTarget(bpfModule)
	initGlobalVars(bpfModule)
	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
	attachPrograms(bpfModule, names)

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
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(opts.duration)*time.Second)
		defer cancel()
	}
	printHeader()

loop:
	for {
		select {
		case data := <-eventsChannel:
			printEvent(data)
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
