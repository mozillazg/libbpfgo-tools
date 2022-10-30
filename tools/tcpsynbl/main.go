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
	Slots [32]uint32
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	ipv4       bool
	ipv6       bool
	interval   uint
	times      uint
}

var opts = Options{
	bpfObjPath: "tcpsynbl.bpf.o",
	verbose:    false,
	timestamp:  false,
	ipv4:       false,
	ipv6:       false,
	interval:   99999999,
	times:      99999999,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.ipv4, "ipv4", "4", opts.ipv4, "Trace IPv4 family only")
	flag.BoolVarP(&opts.ipv6, "ipv6", "6", opts.ipv6, "Trace IPv6 family only")
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

func initGlobalVars(bpfModule *bpf.Module) {

}

func attachPrograms(bpfModule *bpf.Module) {
	var progNames []string
	if opts.ipv4 {
		progNames = append(progNames, "tcp_v4_syn_recv")
	} else if opts.ipv6 {
		progNames = append(progNames, "tcp_v6_syn_recv")
	} else {
		progNames = append(progNames, "tcp_v4_syn_recv")
		progNames = append(progNames, "tcp_v6_syn_recv")
	}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		for _, name := range progNames {
			if prog.Name() == name {
				if _, err := prog.AttachGeneric(); err != nil {
					log.Fatalln(err)
				}
			}
		}
	}
}

func printLog2Hists(hists *bpf.BPFMap) {
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
		fmt.Printf("backlog_max = %d\n", binary.LittleEndian.Uint64(key))
		common.PrintLog2Hist(vals, "backlog")
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
	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
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
	fmt.Printf("Tracing SYN backlog size. Ctrl-C to end.\n")

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
