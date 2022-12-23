package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/mozillazg/libbpfgo-tools/common"
	flag "github.com/spf13/pflag"
)

type Event struct {
	Fpid  uint32
	Tpid  uint32
	Pages uint64
	Fcomm [16]byte
	Tcomm [16]byte
}

type Options struct {
	bpfObjPath string
	verbose    bool
}

var opts = Options{
	bpfObjPath: "oomkill.bpf.o",
	verbose:    false,
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func formatEvent(event Event) {
	ts := time.Now().Format("15:04:05")
	rawLoadAvg, err := os.ReadFile("/proc/loadavg")
	if err == nil {
		loadAvg := strings.TrimSpace(string(rawLoadAvg))
		fmt.Printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %d pages, loadavg: %s\n",
			ts, event.Fpid, common.GoString(event.Fcomm[:]), event.Tpid, common.GoString(event.Tcomm[:]), event.Pages, loadAvg)
	} else {
		fmt.Printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %d pages\n",
			ts, event.Fpid, common.GoString(event.Fcomm[:]), event.Tpid, common.GoString(event.Tcomm[:]), event.Pages)
	}
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

	eventsChannel := make(chan []byte)
	pb, err := bpfModule.InitRingBuf("events", eventsChannel)
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

loop:
	for {
		select {
		case data := <-eventsChannel:
			var event Event
			err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("read data failed: %s\n%v", err, data)
			}
			formatEvent(event)
		case <-ctx.Done():
			break loop
		}
	}
}
