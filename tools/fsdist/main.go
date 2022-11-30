package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const MAX_SLOTS = 32

const (
	READ = iota
	WRITE
	OPEN
	FSYNC
	GETATTR
	MAX_OP
)

const (
	NONE = iota
	BTRFS
	EXT4
	NFS
	XFS
)

type Hist struct {
	Slots [MAX_SLOTS]uint32
}

type HistKey struct {
	CmdFlags uint32
	Dev      uint32
}

type FSConfig struct {
	fs      string
	opFuncs [MAX_OP]string
}

type Options struct {
	bpfObjPath   string
	verbose      bool
	milliseconds bool
	timestamp    bool
	pid          uint32
	_type        string
	interval     uint64
	count        uint64
	fsType       int
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
var fileOpNames [GETATTR + 1]string

var opts = Options{
	bpfObjPath:   "fsdist.bpf.o",
	verbose:      false,
	milliseconds: false,
	timestamp:    false,
	pid:          0,
	_type:        "",
	fsType:       -1,
	interval:     99999999,
	count:        99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Print timestamp")
	flag.BoolVarP(&opts.milliseconds, "milliseconds", "m", opts.milliseconds, "Millisecond histogram")
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

	if args := flag.Args(); len(args) > 0 {
		interval, err := strconv.Atoi(args[0])
		if err != nil || interval <= 0 {
			log.Fatal("invalid internal\n")
		}
		opts.interval = uint64(interval)
		if len(args) > 1 {
			count, err := strconv.Atoi(args[1])
			if err != nil || count <= 0 {
				log.Fatal("invalid count\n")
			}
			opts.count = uint64(count)
		}
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
	fsConfigs[BTRFS].opFuncs[GETATTR] = ""

	fsConfigs[EXT4] = FSConfig{
		fs: "ext4",
	}
	fsConfigs[EXT4].opFuncs[READ] = "ext4_file_read_iter"
	fsConfigs[EXT4].opFuncs[WRITE] = "ext4_file_write_iter"
	fsConfigs[EXT4].opFuncs[OPEN] = "ext4_file_open"
	fsConfigs[EXT4].opFuncs[FSYNC] = "ext4_sync_file"
	fsConfigs[EXT4].opFuncs[GETATTR] = "ext4_file_getattr"

	fsConfigs[NFS] = FSConfig{
		fs: "nfs",
	}
	fsConfigs[NFS].opFuncs[READ] = "nfs_file_read"
	fsConfigs[NFS].opFuncs[WRITE] = "nfs_file_write"
	fsConfigs[NFS].opFuncs[OPEN] = "nfs_file_open"
	fsConfigs[NFS].opFuncs[FSYNC] = "nfs_file_fsync"
	fsConfigs[NFS].opFuncs[GETATTR] = "nfs_getattr"

	fsConfigs[XFS] = FSConfig{
		fs: "xfs",
	}
	fsConfigs[XFS].opFuncs[READ] = "xfs_file_read_iter"
	fsConfigs[XFS].opFuncs[WRITE] = "xfs_file_write_iter"
	fsConfigs[XFS].opFuncs[OPEN] = "xfs_file_open"
	fsConfigs[XFS].opFuncs[FSYNC] = "xfs_file_fsync"
	fsConfigs[XFS].opFuncs[GETATTR] = ""
}

func initFileOpsNames() {
	fileOpNames[READ] = "read"
	fileOpNames[WRITE] = "write"
	fileOpNames[OPEN] = "open"
	fileOpNames[FSYNC] = "fsync"
	fileOpNames[GETATTR] = "getattr"
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
	if opts.milliseconds {
		if err := bpfModule.InitGlobalVariable("in_ms", true); err != nil {
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

	if cfg.opFuncs[GETATTR] != "" {
		fentrySetAttach(bpfModule, "getattr_fentry", cfg.opFuncs[GETATTR])
		programNames = append(programNames, "getattr_fentry")

		fentrySetAttach(bpfModule, "getattr_fexit", cfg.opFuncs[GETATTR])
		programNames = append(programNames, "getattr_fexit")
	}

	return programNames
}

func fentrySetAttach(bpfModule *bpf.Module, funcName, target string) {
	prog, err := bpfModule.GetProgram(funcName)
	if err != nil {
		log.Fatalln(err)
	}
	prog.SetProgramType(bpf.BPFProgTypeTracing)
	prog.SetAttachType(bpf.BPFAttachTypeTraceFentry)
	if err := prog.SetAttachTarget(0, target); err != nil {
		log.Fatalln(err)
	}
}

func printHists(bpfModule *bpf.Module) {
	units := "usecs"
	if opts.milliseconds {
		units = "msecs"
	}
	var hists [MAX_OP]Hist
	rawHists, err := bpfModule.GetGlobalVariableValue("hists")
	if err != nil {
		log.Fatalln(err)
	}
	if err := binary.Read(bytes.NewReader(rawHists), binary.LittleEndian, &hists); err != nil {
		log.Fatalln(err)
	}
	for op := READ; op < MAX_OP; op++ {
		hist := hists[op]
		if hist.Slots[0] == 0 {
			continue
		}
		fmt.Printf("operation = '%s'\n", fileOpNames[op])
		var vals []int
		for _, v := range hist.Slots {
			vals = append(vals, int(v))
		}
		common.PrintLog2Hist(vals, units)
		fmt.Printf("\n")
	}

	if err := bpfModule.UpdateGlobalVariable("hists", [MAX_OP]Hist{}); err != nil {
		log.Fatalln(err)
	}
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()
	ticker := time.NewTicker(time.Second * time.Duration(opts.interval))
	var end bool
	count := opts.count
	fmt.Printf("Tracing %s operation latency... Hit Ctrl-C to end.\n", fsConfigs[opts.fsType].fs)

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
		printHists(bpfModule)

		count--
		if end || count == 0 {
			break loop
		}
	}
}
