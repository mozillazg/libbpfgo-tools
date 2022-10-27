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
	flag "github.com/spf13/pflag"
)

type Event struct {
	Fpid  uint32
	Tpid  uint32
	Pages uint64
	Fcomm [16]byte
	Tcomm [16]byte
}

func (e Event) FcommString() string {
	return string(bytes.TrimRight(e.Fcomm[:], "\x00"))
}

func (e Event) TcommString() string {
	return string(bytes.TrimRight(e.Tcomm[:], "\x00"))
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
			ts, event.Fpid, event.Fcomm, event.Tpid, event.Tcomm, event.Pages, loadAvg)
	} else {
		fmt.Printf("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\"), %d pages\n",
			ts, event.Fpid, event.Fcomm, event.Tpid, event.Tcomm, event.Pages)
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
		case e := <-lostChannel:
			log.Printf("lost %d events", e)
		case <-ctx.Done():
			break loop
		}
	}
}
