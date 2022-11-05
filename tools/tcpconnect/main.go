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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const (
	TASK_COMM_LEN = 16
	MAX_PORTS     = 64
)

var startTs uint64

type Ipv4FlowKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type Ipv6FlowKey struct {
	Saddr common.Uint128
	Daddr common.Uint128
	Sport uint16
	Dport uint16
}

type Event struct {
	Saddr common.Uint128
	Daddr common.Uint128

	Task  [TASK_COMM_LEN]byte
	TsUs  uint64
	Af    uint32
	Pid   uint32
	Uid   uint32
	Sport uint16
	Dport uint16
}

func (e Event) TaskString() string {
	return string(bytes.TrimRight(e.Task[:], "\x00"))
}

func (e Event) SaddrString() string {
	return common.AddrFrom16(uint16(e.Af), e.Saddr).String()
}
func (e Event) DaddrString() string {
	return common.AddrFrom16(uint16(e.Af), e.Daddr).String()
}

func (k Ipv4FlowKey) SaddrString() string {
	return common.InetNtoa(k.Saddr)
}
func (k Ipv4FlowKey) DaddrString() string {
	return common.InetNtoa(k.Daddr)
}

func (k Ipv6FlowKey) SaddrString() string {
	return common.AddrFrom16(common.AF_INET6, k.Saddr).String()
}
func (k Ipv6FlowKey) DaddrString() string {
	return common.AddrFrom16(common.AF_INET6, k.Daddr).String()
}

type Options struct {
	bpfObjPath string
	verbose    bool
	timestamp  bool
	count      bool
	printUid   bool
	pid        uint32
	uid        uint32
	sourcePort bool
	port       []uint
}

var opts = Options{
	bpfObjPath: "tcpconnect.bpf.o",
	verbose:    false,
	timestamp:  false,
	count:      false,
	printUid:   false,
	pid:        0,
	uid:        0,
	sourcePort: false,
	port:       nil,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.BoolVarP(&opts.timestamp, "timestamp", "t", opts.timestamp, "Include timestamp on output")
	flag.BoolVarP(&opts.count, "count", "c", opts.count, "Count connects per src ip and dst ip/port")
	flag.BoolVarP(&opts.printUid, "print-uid", "U", opts.printUid, "Include UID on output")
	flag.BoolVarP(&opts.sourcePort, "source-port", "s", opts.sourcePort, "Consider source port when counting")
	flag.Uint32VarP(&opts.pid, "pid", "p", opts.pid, "Process PID to trace")
	flag.Uint32VarP(&opts.uid, "uid", "u", opts.uid, "Process UID to trace")
	flag.UintSliceVarP(&opts.port, "port", "P", opts.port, "Comma-separated list of destination ports to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	if opts.count {
		if err := bpfModule.InitGlobalVariable("do_count", true); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.pid > 0 {
		if err := bpfModule.InitGlobalVariable("filter_pid", opts.pid); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.uid > 0 {
		if err := bpfModule.InitGlobalVariable("filter_uid", opts.uid); err != nil {
			log.Fatalln(err)
		}
	}
	if len(opts.port) > 0 {
		if err := bpfModule.InitGlobalVariable("filter_ports_len", len(opts.port)); err != nil {
			log.Fatalln(err)
		}
		var vals [MAX_PORTS]uint32
		for i, v := range opts.port {
			vals[i] = uint32(v)
		}
		if err := bpfModule.InitGlobalVariable("filter_ports", vals); err != nil {
			log.Fatalln(err)
		}
	}
	if opts.sourcePort {
		if err := bpfModule.InitGlobalVariable("source_port", true); err != nil {
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

func printCountIpv4(ipv4Count *bpf.BPFMap) {
	items, err := common.DumpHash(ipv4Count)
	if err != nil {
		log.Fatalln(err)
	}
	for _, ret := range items {
		var key Ipv4FlowKey
		if err := binary.Read(bytes.NewReader(ret[0]), binary.LittleEndian, &key); err != nil {
			log.Fatalln(err)
		}
		var value uint64
		if err := binary.Read(bytes.NewReader(ret[1]), binary.LittleEndian, &value); err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%-25s %-25s", key.SaddrString(), key.DaddrString())
		if opts.sourcePort {
			fmt.Printf(" %-20d", key.Sport)
		}
		fmt.Printf(" %-20d", common.Ntohs(key.Dport))
		fmt.Printf(" %-10d", value)
		fmt.Printf("\n")
	}
}

func printCountIpv6(ipv6Count *bpf.BPFMap) {
	items, err := common.DumpHash(ipv6Count)
	if err != nil {
		log.Fatalln(err)
	}
	for _, ret := range items {
		var key Ipv6FlowKey
		if err := binary.Read(bytes.NewReader(ret[0]), binary.LittleEndian, &key); err != nil {
			log.Fatalln(err)
		}
		var value uint64
		if err := binary.Read(bytes.NewReader(ret[1]), binary.LittleEndian, &value); err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%-25s %-25s", key.SaddrString(), key.DaddrString())
		if opts.sourcePort {
			fmt.Printf(" %-20d", key.Sport)
		}
		fmt.Printf(" %-20d", common.Ntohs(key.Dport))
		fmt.Printf(" %-10d", value)
		fmt.Printf("\n")
	}
}

func printCount(ctx context.Context, bpfModule *bpf.Module) {
	ipv4Count, err := bpfModule.GetMap("ipv4_count")
	if err != nil {
		log.Fatalln(err)
	}
	ipv6Count, err := bpfModule.GetMap("ipv6_count")
	if err != nil {
		log.Fatalln(err)
	}
	<-ctx.Done()

	fmt.Printf("\n%-25s %-25s", "LADDR", "RADDR")
	if opts.sourcePort {
		fmt.Printf(" %-20s", "LPORT")
	}
	fmt.Printf(" %-20s", "RPORT")
	fmt.Printf(" %-10s", "CONNECTS")
	fmt.Printf("\n")

	printCountIpv4(ipv4Count)
	printCountIpv6(ipv6Count)
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
		fmt.Printf("%-9.3f", float64(e.TsUs-startTs)/1000000.0)
	}
	if opts.printUid {
		fmt.Printf("%-6d", e.Uid)
	}
	af := 4
	if e.Af == common.AF_INET6 {
		af = 6
	}
	fmt.Printf("%-6d %-12.12s %-2d %-16s %-16s",
		e.Pid, e.TaskString(), af, e.SaddrString(), e.DaddrString())
	if opts.sourcePort {
		fmt.Printf(" %-5d", e.Sport)
	}
	fmt.Printf(" %-5d", common.Ntohs(e.Dport))
	fmt.Printf("\n")
}

func printEvents(ctx context.Context, bpfModule *bpf.Module) {
	eventsChannel := make(chan []byte)
	lostChannel := make(chan uint64)
	pb, err := bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		log.Fatalln(err)
	}
	pb.Start()
	defer func() {
		pb.Stop()
		pb.Close()
	}()

	if opts.timestamp {
		fmt.Printf("%-9s", "TIME(s)")
	}
	if opts.printUid {
		fmt.Printf("%-6s", "UID")
	}
	fmt.Printf("%-6s %-12s %-2s %-16s %-16s", "PID", "COMM", "IP", "SADDR", "DADDR")
	if opts.sourcePort {
		fmt.Printf(" %-5s", "SPORT")
	}
	fmt.Printf(" %-5s\n", "DPORT")

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

func main() {
	flag.Parse()

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if opts.count {
		printCount(ctx, bpfModule)
	} else {
		printEvents(ctx, bpfModule)
	}
}
