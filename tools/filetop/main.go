package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	flag "github.com/spf13/pflag"
)

const (
	PATH_MAX          = 4096
	TASK_COMM_LEN     = 16
	OUTPUT_ROWS_LIMIT = 10240
)

const (
	ALL = iota
	READS
	WRITES
	RBYTES
	WBYTES
)

type FileStatBase struct {
	Reads      uint64
	ReadBytes  uint64
	Writes     uint64
	WriteBytes uint64
	Pid        uint32
	Tid        uint32
}

type FileExtra struct {
	Common [TASK_COMM_LEN]byte
	Type   byte
}

type FileStat struct {
	FileStatBase
	FileExtra
	filename [PATH_MAX]byte
}

func (s FileStat) Common() string {
	return string(bytes.TrimRight(s.FileExtra.Common[:], "\x00"))
}
func (s FileStat) Filename() string {
	return strings.Split(string(bytes.TrimRight(s.filename[:], "\x00")), "\x00")[0]
}

type Options struct {
	bpfObjPath string
	verbose    bool
	pid        uint32
	noclear    bool
	all        bool
	sort       string
	rows       uint
	interval   uint64
	count      uint64
	sortBy     int
}

var opts = Options{
	bpfObjPath: "filetop.bpf.o",
	verbose:    false,
	pid:        0,
	noclear:    false,
	all:        false,
	sort:       "all",
	rows:       20,
	interval:   1,
	count:      99999999,
	sortBy:     0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process ID to trace")
	flag.BoolVarP(&opts.noclear, "noclear", "C", opts.noclear, "Don't clear the screen")
	flag.BoolVarP(&opts.all, "all", "a", opts.all, "Include special files")
	flag.StringVarP(&opts.sort, "sort", "s", opts.sort, "Sort columns, default all [all, reads, writes, rbytes, wbytes]")
	flag.UintVarP(&opts.rows, "rows", "r", opts.rows, "Maximum rows to print, default 20")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
	switch opts.sort {
	case "reads":
		opts.sortBy = READS
	case "writes":
		opts.sortBy = WRITES
	case "rbytes":
		opts.sortBy = RBYTES
	case "wbytes":
		opts.sortBy = WBYTES
	default:
		opts.sortBy = ALL
	}
	if opts.rows > OUTPUT_ROWS_LIMIT {
		opts.rows = OUTPUT_ROWS_LIMIT
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
				log.Fatal("invalid times\n")
			}
			opts.count = uint64(count)
		}
	}
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("target_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.all {
		if err := bpfModule.InitGlobalVariable("regular_file_only", false); err != nil {
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

func parseStat(data []byte) FileStat {
	base := FileStatBase{}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &base); err != nil {
		log.Fatalln(err)
	}
	extra := FileExtra{}
	length := len(data)
	if err := binary.Read(bytes.NewReader(data[length-8-TASK_COMM_LEN:length]), binary.LittleEndian, &extra); err != nil {
		log.Fatalln(err)
	}

	stat := FileStat{
		FileStatBase: base,
		FileExtra:    extra,
	}
	if err := binary.Read(bytes.NewReader(data[40:length-8-TASK_COMM_LEN]), binary.LittleEndian, &stat.filename); err != nil {
		log.Fatalln(err)
	}
	return stat
}

func sortColumn(values []FileStat) {
	sort.Slice(values, func(i, j int) bool {
		switch opts.sortBy {
		case READS:
			return values[i].Reads > values[j].Reads
		case WRITES:
			return values[i].Writes > values[j].Writes
		case RBYTES:
			return values[i].ReadBytes > values[j].ReadBytes
		case WBYTES:
			return values[i].WriteBytes > values[j].WriteBytes
		default:
			return (values[i].Reads + values[i].Writes + values[i].ReadBytes + values[i].WriteBytes) >
				(values[j].Reads + values[j].Writes + values[j].ReadBytes + values[j].WriteBytes)
		}
	})
}

func printStat(entries *bpf.BPFMap) {
	loadData, _ := os.ReadFile("/proc/loadavg")
	if len(loadData) > 0 {
		ts := time.Now().Format("15:04:05")
		load := string(bytes.TrimSpace(loadData))
		if load != "" {
			fmt.Printf("%8s loadavg: %s\n", ts, load)
		}
	}

	fmt.Printf("%-7s %-16s %-6s %-6s %-7s %-7s %1s %s\n",
		"TID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE")
	iter := entries.Iterator()
	var values []FileStat
	for iter.Next() {
		key := iter.Key()
		value, err := entries.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			log.Fatalf("failed to lookup entry: %s", err)
		}

		stat := parseStat(value)
		values = append(values, stat)
	}

	sortColumn(values)
	rows := len(values)
	if rows > int(opts.rows) {
		rows = int(opts.rows)
	}
	for i := 0; i < rows; i++ {
		fmt.Printf("%-7d %-16s %-6d %-6d %-7d %-7d %c %s\n",
			values[i].Tid, values[i].Common(), values[i].Reads, values[i].Writes,
			values[i].ReadBytes/1024, values[i].WriteBytes/1024,
			values[i].Type, values[i].Filename())
	}
	fmt.Printf("\n")

	iter = entries.Iterator()
	for iter.Next() {
		key := iter.Key()
		if err := entries.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			log.Fatalf("failed to cleanup entry: %s", err)
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
	loadBPFObj(bpfModule)
	applyFilters(bpfModule)
	attachPrograms(bpfModule)

	entries, err := bpfModule.GetMap("entries")
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()
	ticker := time.NewTicker(time.Second * time.Duration(opts.interval))
	var end bool
	count := opts.count

loop:
	for {
		select {
		case <-ctx.Done():
			end = true
			break
		case <-ticker.C:
			break
		}
		if !opts.noclear {
			cmd := exec.Command("clear")
			cmd.Stdout = os.Stdout
			if err := cmd.Run(); err != nil {
				log.Fatalln(err)
			}
		}

		printStat(entries)

		count--
		if end || count == 0 {
			break loop
		}
	}
}
