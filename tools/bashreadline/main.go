package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/helpers"
	flag "github.com/spf13/pflag"
)

type Options struct {
	bpfObjPath string
	verbose    bool
	shared     string
}

var opts = Options{
	bpfObjPath: "bashreadline.bpf.o",
	verbose:    false,
	shared:     "",
}

func init() {
	flag.StringVar(&opts.bpfObjPath, "objpath", opts.bpfObjPath, "Path to the bpf object file")
	flag.StringVarP(&opts.shared, "shared", "s", opts.shared, "the location of libreadline.so library")
	// flag.BoolVarP(&opts.verbose, "verbose", "v", opts.verbose, "Verbose debug output")
}

func parseArgs() {
	flag.Parse()
}

func findReadlineSo() string {
	bashPath := "/bin/bash"
	offset, err := helpers.SymbolToOffset(bashPath, "readline")
	if err == nil && offset > 0 {
		return bashPath
	}

	out, err := exec.Command("ldd", "/bin/bash").Output()
	if err != nil {
		log.Fatalf("failed to find readline: %s", err)
	}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		line := s.Text()
		if !strings.Contains(line, " => ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && strings.Contains(line, "/libreadline.so") {
			return strings.TrimSpace(fields[2])
		}
	}
	log.Fatal("failed to find readline")
	return ""
}

func printEvent(data []byte) {
	var pid uint32
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &pid); err != nil {
		log.Fatalf("read data failed: %s\n%v", err, data)
	}
	str := data[4:]
	str = str[:bytes.IndexByte(str, 0)]

	ts := time.Now().Format("15:04:05")
	fmt.Printf("%-9s %-7d %s\n", ts, pid, str)
}

func initGlobalVars(bpfModule *bpf.Module) {
}

func attachPrograms(bpfModule *bpf.Module) {
	readlineSoPath := opts.shared
	if readlineSoPath == "" {
		readlineSoPath = findReadlineSo()
	}
	funcOff, err := helpers.SymbolToOffset(readlineSoPath, "readline")
	if err != nil || funcOff <= 0 {
		log.Fatalf("cound not find readline in %s\n", readlineSoPath)
	}

	prog, err := bpfModule.GetProgram("printret")
	if err != nil {
		log.Fatalln(err)
	}
	if _, err := prog.AttachURetprobe(-1, readlineSoPath, funcOff); err != nil {
		log.Fatalln(err)
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

	fmt.Printf("%-9s %-7s %s\n", "TIME", "PID", "COMMAND")

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
