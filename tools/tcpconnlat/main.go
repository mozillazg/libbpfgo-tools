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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

var startTs uint64

type Event struct {
	Saddr   [16]byte
	Daddr   [16]byte
	Comm    [16]byte
	DeltaUs uint64
	TsUs    uint64
	Tgid    uint32
	Af      uint32
	Lport   uint16
	Dport   uint16
}

func (e Event) CommString() string {
	return string(bytes.TrimRight(e.Comm[:], "\x00"))
}

func (e Event) SaddrString() string {
	return common.AddrFrom16(uint16(e.Af), e.Saddr).String()
}
func (e Event) DaddrString() string {
	return common.AddrFrom16(uint16(e.Af), e.Daddr).String()
}

type Options struct {
	bpfObjPath string
	verbose    bool
	pid        uint32
	lport      bool
	timestamp  bool
	minUs      uint64
}

var opts = Options{
	bpfObjPath: "tcpconnlat.bpf.o",
	verbose:    false,
	pid:        0,
	lport:      false,
	timestamp:  false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Trace this PID only")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.lport, "lport", "L", opts.lport, "Include LPORT on output")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("targ_tgid", &opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.minUs > 0 {
		if err := bpfModule.InitGlobalVariable("targ_min_us", &opts.minUs); err != nil {
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
		if _, err := prog.AttachGeneric(); err != nil {
			log.Fatalln(err)
		}
	}
}

func printEvent(data []byte) {
	var e Event
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e)
	if err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}

	if opts.timestamp {
		if startTs == 0 {
			startTs = e.TsUs
		}
		fmt.Printf("%-9.3f ", float64(e.TsUs-startTs)/1000000.0)
	}
	af := 4
	if e.Af == common.AF_INET6 {
		af = 6
	}

	if opts.lport {
		fmt.Printf("%-6d %-12.12s %-2d %-16s %-6d %-16s %-5d %.2f\n", e.Tgid, e.CommString(),
			af, e.SaddrString(), e.Lport, e.DaddrString(), common.Ntohs(e.Dport), float64(e.DeltaUs)/1000.0)
	} else {
		fmt.Printf("%-6d %-12.12s %-2d %-16s %-16s %-5d %.2f\n", e.Tgid, e.CommString(),
			af, e.SaddrString(), e.DaddrString(), common.Ntohs(e.Dport), float64(e.DeltaUs)/1000.0)
	}
}

func main() {
	flag.Parse()
	if args := flag.Args(); len(args) > 0 {
		ms, err := strconv.ParseFloat(args[0], 64)
		if err != nil || ms <= 0 {
			log.Fatalf("Invalid delay (in us): %s\n", args[0])
		}
		opts.minUs = uint64(ms * 1000)
	}

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

	if opts.timestamp {
		fmt.Printf("%-9s ", ("TIME(s)"))
	}
	if opts.lport {
		fmt.Printf("%-6s %-12s %-2s %-16s %-6s %-16s %-5s %s\n",
			"PID", "COMM", "IP", "SADDR", "LPORT", "DADDR", "DPORT", "LAT(ms)")
	} else {
		fmt.Printf("%-6s %-12s %-2s %-16s %-16s %-5s %s\n",
			"PID", "COMM", "IP", "SADDR", "DADDR", "DPORT", "LAT(ms)")
	}
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
