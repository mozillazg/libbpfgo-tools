module github.com/mozillazg/libbpfgo-tools/tools/bashreadline

go 1.18

require (
	github.com/aquasecurity/libbpfgo v0.4.5-libbpf-1.0.1
	github.com/aquasecurity/libbpfgo/helpers v0.4.5
	github.com/mozillazg/libbpfgo-tools/common v0.0.0
	github.com/spf13/pflag v1.0.5
)

require golang.org/x/sys v0.1.0 // indirect

replace github.com/mozillazg/libbpfgo-tools/common v0.0.0 => ../../common
