package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const MAX_SLOTS = 27

type Hist struct {
	Latency uint64
	Cnt     uint64
	Slots   [MAX_SLOTS]uint32
}

type Options struct {
	bpfObjPath  string
	verbose     bool
	timestamp   bool
	millisecond bool
	byladdr     bool
	byraddr     bool
	extension   bool
	interval    uint64
	duration    uint64
	lport       uint16
	rport       uint16
	laddr       string
	laddrV      uint32
	raddr       string
	raddrV      uint32
}

var opts = Options{
	bpfObjPath:  "tcprtt.bpf.o",
	verbose:     false,
	timestamp:   false,
	millisecond: false,
	byladdr:     false,
	byraddr:     false,
	extension:   false,
	interval:    99999999,
	duration:    0,
	lport:       0,
	rport:       0,
	laddr:       "",
	raddr:       "",
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint64VarP(&opts.interval, "interval", "i", opts.interval, "summary interval, seconds")
	flag.Uint64VarP(&opts.duration, "duration", "d", opts.duration, "total duration of trace, seconds")
	flag.BoolVarP(&opts.timestamp, "timestamp", "T", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.millisecond, "millisecond", "m", opts.millisecond, "millisecond histogram")
	flag.Uint16VarP(&opts.lport, "lport", "p", opts.lport, "filter for local port")
	flag.Uint16VarP(&opts.rport, "rport", "P", opts.rport, "filter for remote port")
	flag.StringVarP(&opts.laddr, "laddr", "a", opts.laddr, "filter for local address")
	flag.StringVarP(&opts.raddr, "raddr", "A", opts.raddr, "filter for remote address")
	flag.BoolVarP(&opts.byladdr, "byladdr", "b", opts.byladdr, "show sockets histogram by local address")
	flag.BoolVarP(&opts.byraddr, "byraddr", "B", opts.byraddr, "show sockets histogram by remote address")
	flag.BoolVarP(&opts.extension, "extension", "e", opts.extension, "show extension summary(average)")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
	if opts.lport > 0 {
		opts.lport = common.Htons(opts.lport)
	}
	if opts.rport > 0 {
		opts.rport = common.Htons(opts.rport)
	}
	if opts.laddr != "" {
		addr, err := common.InetAton(opts.laddr)
		if err != nil {
			log.Fatalf("invalid local address: %s", opts.laddr)
		}
		opts.laddrV = addr
	}
	if opts.raddr != "" {
		addr, err := common.InetAton(opts.raddr)
		if err != nil {
			log.Fatalf("invalid local address: %s", opts.laddr)
		}
		opts.raddrV = addr
	}
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.byladdr {
		if err := bpfModule.InitGlobalVariable("targ_laddr_hist", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.byraddr {
		if err := bpfModule.InitGlobalVariable("targ_raddr_hist", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.extension {
		if err := bpfModule.InitGlobalVariable("targ_show_ext", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.millisecond {
		if err := bpfModule.InitGlobalVariable("targ_ms", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.lport > 0 {
		if err := bpfModule.InitGlobalVariable("targ_sport", opts.lport); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.rport > 0 {
		if err := bpfModule.InitGlobalVariable("targ_dport", opts.rport); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.laddrV > 0 {
		if err := bpfModule.InitGlobalVariable("targ_saddr", opts.laddrV); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.raddrV > 0 {
		if err := bpfModule.InitGlobalVariable("targ_daddr", opts.raddrV); err != nil {
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
	attachNames := []string{"tcp_rcv"}
	progIter := bpfModule.Iterator()
	for {
		prog := progIter.NextProgram()
		if prog == nil {
			break
		}
		if !common.Contains(attachNames, prog.Name()) {
			continue
		}
		_, err := prog.AttachGeneric()
		if err != nil {
			log.Fatalln(err)
		}
	}
}

func printMap(hists *bpf.BPFMap) {
	units := "usecs"
	if opts.millisecond {
		units = "msecs"
	}
	iter := hists.Iterator()
	for iter.Next() {
		key := iter.Key()
		value, err := hists.GetValue(unsafe.Pointer(&key[0]))
		if err != nil {
			log.Fatalf("failed to lookup infos: %s", err)
		}
		var hist Hist
		if err := binary.Read(bytes.NewReader(value), binary.LittleEndian, &hist); err != nil {
			log.Fatalln(err)
		}

		addr := binary.LittleEndian.Uint32(key)
		if opts.byladdr {
			fmt.Printf("Local Address = %s ", common.InetNtoa(addr))
		} else if opts.byraddr {
			fmt.Printf("Remote Address = %s ", common.InetNtoa(addr))
		} else {
			fmt.Printf("All Addresses = ****** ")
		}
		if opts.extension {
			fmt.Printf("[AVG %d]", hist.Latency/hist.Cnt)
		}
		fmt.Printf("\n")
		var vals []int
		for _, v := range hist.Slots {
			vals = append(vals, int(v))
		}
		common.PrintLog2Hist(vals, units)
	}

	iter = hists.Iterator()
	for iter.Next() {
		key := iter.Key()
		if err := hists.DeleteKey(unsafe.Pointer(&key[0])); err != nil {
			log.Fatalf("failed to cleanup infos: %s", err)
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

	hists, err := bpfModule.GetMap("hists")
	if err != nil {
		log.Fatalln(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()
	ticker := time.NewTicker(time.Second * time.Duration(opts.interval))
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(opts.duration))
		defer cancel()
	}
	var end bool

	fmt.Printf("Tracing TCP RTT")
	if opts.duration > 0 {
		fmt.Printf(" for %d secs.\n", opts.duration)
	} else {
		fmt.Printf("... Hit Ctrl-C to end.\n")
	}

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
			fmt.Printf("%-8s\n", time.Now().Format("15:04:05"))
		}
		printMap(hists)

		if end {
			break loop
		}
	}
}
