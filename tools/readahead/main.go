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

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

const maxSlots = 20

type Hist struct {
	Unused uint32
	Total  uint32
	Slots  [maxSlots]uint32
}

type Options struct {
	bpfObjPath string
	verbose    bool
	duration   uint64
}

var opts = Options{
	bpfObjPath: "readahead.bpf.o",
	verbose:    false,
	duration:   0,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.Uint64VarP(&opts.duration, "duration", "d", opts.duration, "Duration to trace")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func initGlobalVars(bpfModule *bpf.Module) {
	//
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
	var histp Hist
	err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &histp)
	if err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}
	fmt.Printf("Readahead unused/total pages: %d/%d\n",
		histp.Unused, histp.Total)

	var vals []int
	for _, v := range histp.Slots {
		vals = append(vals, int(v))
	}
	common.PrintLog2Hist(vals, "msecs")
}

func main() {
	flag.Parse()

	bpfModule, err := bpf.NewModuleFromFile(opts.bpfObjPath)
	if err != nil {
		log.Fatalln(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalln(err)
	}
	initGlobalVars(bpfModule)
	attachPrograms(bpfModule)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer func() {
		stop()
	}()

	fmt.Printf("Tracing fs read-ahead ... Hit Ctrl-C to end.\n")
	if opts.duration > 0 {
		time.Sleep(time.Second * time.Duration(opts.duration))
		stop()
	}
	<-ctx.Done()

	data, err := bpfModule.GetGlobalVariableValue("hist")
	if err != nil {
		log.Fatalln(err)
	}
	printEvent(data)
}
