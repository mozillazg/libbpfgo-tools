module github.com/mozillazg/libbpfgo-tools/tools/wakeuptime

go 1.18

require (
	github.com/aquasecurity/libbpfgo v0.4.9-libbpf-1.2.0
	github.com/mozillazg/libbpfgo-tools/common v0.0.0
	github.com/spf13/pflag v1.0.5
)

replace github.com/mozillazg/libbpfgo-tools/common v0.0.0 => ../../common
